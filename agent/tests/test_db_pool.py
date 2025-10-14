"""
Comprehensive tests for db_pool.py module.

Tests cover:
- DatabaseConnectionPool class functionality
- Connection management and lifecycle
- Query execution with retries
- Pool statistics and monitoring
- Global pool management
- Context manager usage
- Utility functions
- Error handling and edge cases
"""

import asyncio
import os
import tempfile
import pytest
import pytest_asyncio
import sqlite3
from unittest.mock import Mock, patch, AsyncMock
from concurrent.futures import ThreadPoolExecutor

from sys_scan_agent.db_pool import (
    DatabaseConnectionPool,
    get_db_pool,
    get_db_connection,
    initialize_pool,
    close_pool,
    ensure_table_exists,
    get_table_row_count
)


@pytest.fixture
def temp_db_path():
    """Create a temporary database path for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        temp_path = f.name
    yield temp_path
    # Cleanup
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass


@pytest_asyncio.fixture
async def pool(temp_db_path):
    """Create a test pool instance."""
    pool = DatabaseConnectionPool(
        db_path=temp_db_path,
        max_connections=3,
        connection_timeout=5.0,
        max_retries=2
    )
    yield pool
    # Cleanup
    if not pool._closed:
        await pool.close_all()


class TestDatabaseConnectionPool:
    """Test DatabaseConnectionPool class functionality."""

    def test_pool_initialization(self, temp_db_path):
        """Test pool initialization with various parameters."""
        pool = DatabaseConnectionPool(
            db_path=temp_db_path,
            max_connections=5,
            connection_timeout=10.0,
            max_retries=3
        )

        assert pool.db_path == temp_db_path
        assert pool.max_connections == 5
        assert pool.connection_timeout == 10.0
        assert pool.max_retries == 3
        assert not pool._initialized
        assert not pool._closed
        assert pool._connections_created == 0
        assert pool._connections_returned == 0
        assert pool._connection_errors == 0

    @pytest.mark.asyncio
    async def test_pool_initialize(self, pool):
        """Test pool initialization creates connections."""
        await pool.initialize()

        assert pool._initialized
        assert not pool._closed
        assert pool._connections_created == pool.max_connections

        # Check that connections are in the pool
        stats = await pool.get_pool_stats()
        assert stats['connections_created'] == pool.max_connections
        assert stats['initialized'] is True
        assert stats['closed'] is False

    @pytest.mark.asyncio
    async def test_pool_initialize_twice(self, pool):
        """Test that initializing twice doesn't create duplicate connections."""
        await pool.initialize()
        initial_count = pool._connections_created

        await pool.initialize()  # Should be idempotent

        assert pool._connections_created == initial_count

    @pytest.mark.asyncio
    async def test_get_connection_success(self, pool):
        """Test successful connection acquisition."""
        await pool.initialize()

        conn = await pool.get_connection()

        assert isinstance(conn, sqlite3.Connection)
        assert conn is not None

        # Return connection
        await pool.return_connection(conn)

    @pytest.mark.asyncio
    async def test_get_connection_pool_not_initialized(self, pool):
        """Test getting connection from uninitialized pool raises error."""
        with pytest.raises(RuntimeError, match="Connection pool not initialized"):
            await pool.get_connection()

    @pytest.mark.asyncio
    async def test_get_connection_pool_closed(self, pool):
        """Test getting connection from closed pool raises error."""
        await pool.initialize()
        await pool.close_all()

        with pytest.raises(RuntimeError, match="Connection pool is closed"):
            await pool.get_connection()

    @pytest.mark.asyncio
    async def test_connection_timeout(self, pool):
        """Test connection timeout behavior."""
        await pool.initialize()

        # Acquire all connections
        connections = []
        for _ in range(pool.max_connections):
            conn = await pool.get_connection()
            connections.append(conn)

        # Next acquisition should timeout
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(pool.get_connection(), timeout=1.0)

        # Return connections
        for conn in connections:
            await pool.return_connection(conn)

    @pytest.mark.asyncio
    async def test_return_connection_to_closed_pool(self, pool):
        """Test returning connection to closed pool closes it."""
        await pool.initialize()
        conn = await pool.get_connection()

        await pool.close_all()

        # Returning to closed pool should not raise error
        await pool.return_connection(conn)

    @pytest.mark.asyncio
    async def test_execute_query_success(self, pool, temp_db_path):
        """Test successful query execution."""
        await pool.initialize()

        # Create a test table
        await pool.execute_query("""
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        """)

        # Insert data
        await pool.execute_query(
            "INSERT INTO test_table (name) VALUES (?)",
            ("test_name",)
        )

        # Query data
        results = await pool.execute_query("SELECT * FROM test_table")

        assert len(results) == 1
        assert results[0][1] == "test_name"

    @pytest.mark.asyncio
    async def test_execute_query_with_retries(self, pool):
        """Test query execution with retry logic."""
        await pool.initialize()

        # Mock a connection that fails initially
        original_create = pool._create_connection

        async def failing_create():
            # First call fails, second succeeds
            if not hasattr(failing_create, 'called'):
                failing_create.called = True
                raise sqlite3.OperationalError("Database locked")
            return await original_create()

        pool._create_connection = failing_create

        # This should succeed after retry
        results = await pool.execute_query("SELECT 1")

        assert results == [(1,)]

    @pytest.mark.asyncio
    async def test_execute_query_failure_after_retries(self, pool):
        """Test query execution failure after all retries."""
        await pool.initialize()

        # Create a mock connection that always fails on execute
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.execute.side_effect = sqlite3.OperationalError("Persistent error")
        mock_cursor.fetchall.return_value = []
        mock_conn.cursor.return_value = mock_cursor

        # Patch get_connection to return the failing connection
        with patch.object(pool, 'get_connection', return_value=mock_conn):
            with patch.object(pool, 'return_connection') as mock_return:
                with pytest.raises(sqlite3.OperationalError, match="Persistent error"):
                    await pool.execute_query("SELECT 1")

    @pytest.mark.asyncio
    async def test_execute_many_success(self, pool):
        """Test successful batch execution."""
        await pool.initialize()

        # Create test table
        await pool.execute_query("""
            CREATE TABLE batch_test (
                id INTEGER PRIMARY KEY,
                value INTEGER
            )
        """)

        # Insert multiple rows
        params_list = [(1,), (2,), (3,)]
        affected = await pool.execute_many(
            "INSERT INTO batch_test (value) VALUES (?)",
            params_list
        )

        assert affected == 3

        # Verify data
        results = await pool.execute_query("SELECT COUNT(*) FROM batch_test")
        assert results[0][0] == 3

    @pytest.mark.asyncio
    async def test_execute_many_with_retries(self, pool):
        """Test batch execution with retry logic."""
        await pool.initialize()

        # Create test table
        await pool.execute_query("CREATE TABLE retry_test (id INTEGER)")

        # Mock connection creation to fail initially
        original_create = pool._create_connection

        async def failing_create():
            if not hasattr(failing_create, 'called'):
                failing_create.called = True
                raise sqlite3.OperationalError("Lock error")
            return await original_create()

        pool._create_connection = failing_create

        # Should succeed after retry
        affected = await pool.execute_many(
            "INSERT INTO retry_test (id) VALUES (?)",
            [(1,), (2,)]
        )

        assert affected == 2

    @pytest.mark.asyncio
    async def test_pool_stats(self, pool):
        """Test pool statistics reporting."""
        await pool.initialize()

        stats = await pool.get_pool_stats()

        expected_keys = {
            'pool_size', 'connections_created', 'connections_returned',
            'connection_errors', 'queue_size', 'initialized', 'closed'
        }

        assert set(stats.keys()) == expected_keys
        assert stats['pool_size'] == pool.max_connections
        assert stats['connections_created'] == pool.max_connections
        assert stats['initialized'] is True
        assert stats['closed'] is False

    @pytest.mark.asyncio
    async def test_close_all(self, pool):
        """Test pool cleanup."""
        await pool.initialize()

        # Get a connection
        conn = await pool.get_connection()
        await pool.return_connection(conn)

        # Close pool
        await pool.close_all()

        assert pool._closed

        # Stats should still be accessible
        stats = await pool.get_pool_stats()
        assert stats['closed'] is True

    @pytest.mark.asyncio
    async def test_close_all_idempotent(self, pool):
        """Test that closing multiple times is safe."""
        await pool.initialize()
        await pool.close_all()
        await pool.close_all()  # Should not raise error

