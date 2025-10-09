# ╔══════════════════════════════════╗
# ║             MazzLabs             ║
# ╟──────────────────────────────────╢
# ║           Joseph Mazzini         ║
# ╚══════════════════════════════════╝

# ==============================================================================
"""
Lion Optimizer Batch Size Configuration

Optimizes batch sizes for Lion optimizer on AWS g5.4xlarge instances,
leveraging Lion's memory efficiency advantages over Adam optimizer.
"""

# Lion optimizer batch size optimization for g5.4xlarge
# Lion handles larger batches more efficiently than Adam

def get_optimal_batch_size(num_gpus=2, gpu_memory_gb=24):
    """Calculate optimal batch size for Lion optimizer"""
    # Lion uses less memory per parameter than Adam
    # Can increase batch size by ~50% vs Adam
    base_batch_per_gpu = 12  # vs 8 for Adam
    return base_batch_per_gpu * num_gpus

# For your g5.4xlarge setup:
BATCH_SIZE_PER_GPU = 12  # Lion efficiency gain
GLOBAL_BATCH_SIZE = 24   # 12 * 2 GPUs