module;
#include <QJsonDocument>
#include <QJsonObject>
#include <QDir>
#include <QLocalSocket>
#include <QTimer>

module sys_scan.ui.ipc;

namespace sys_scan::ui {

    IpcService::IpcService(QObject* parent) : QObject(parent) {
        m_socket = new QLocalSocket(this);
        m_retryTimer = new QTimer(this);
        m_status = QStringLiteral("Disconnected");

        connect(m_socket, &QLocalSocket::connected, this, [this]() {
            m_status = QStringLiteral("Connected to Graph");
            emit connectionChanged();
            emit statusChanged();
            m_retryTimer->stop();
        });

        connect(m_socket, &QLocalSocket::disconnected, this, [this]() {
            m_status = QStringLiteral("Disconnected (Retrying...)");
            emit connectionChanged();
            emit statusChanged();
            m_retryTimer->start(2000);
        });

        connect(m_socket, &QLocalSocket::readyRead, this, &IpcService::onReadyRead);
        connect(m_socket, qOverload<QLocalSocket::LocalSocketError>(&QLocalSocket::errorOccurred),
                this, &IpcService::onError);

        connect(m_retryTimer, &QTimer::timeout, this, [this]() {
            if (m_socket->state() != QLocalSocket::ConnectedState) {
                connectToGraph();
            }
        });

        // Auto-connect on startup
        connectToGraph();
    }

    bool IpcService::isConnected() const {
        return m_socket && m_socket->state() == QLocalSocket::ConnectedState;
    }

    QString IpcService::statusMessage() const {
        return m_status;
    }

    void IpcService::connectToGraph() {
        // Matches the IPC path used by the Python graph
        if (m_socket->state() == QLocalSocket::ConnectedState) return;
        m_socket->connectToServer(QStringLiteral("/tmp/sys-scan-ui.sock"));
    }

    void IpcService::onError(QLocalSocket::LocalSocketError socketError) {
        Q_UNUSED(socketError);
        m_status = QStringLiteral("Connection Error");
        emit statusChanged();
        // schedule retry
        m_retryTimer->start(2000);
    }

    void IpcService::onReadyRead() {
        while (m_socket->canReadLine()) {
            QByteArray data = m_socket->readLine().trimmed();
            QJsonDocument doc = QJsonDocument::fromJson(data);
            if (!doc.isObject()) continue;

            QJsonObject root = doc.object();
            QString type = root.value("type").toString();
            if (type == QLatin1String("investigation_summary")) {
                QString path = root.value("report_path").toString();
                emit analysisCompleted(path);
                m_status = QStringLiteral("New Analysis Available");
                emit statusChanged();
            } else if (type == QLatin1String("status_update")) {
                m_status = root.value("message").toString();
                emit statusChanged();
            }
        }
    }

}

// Ensure moc symbols for Q_OBJECT are emitted in this TU
#include "ipc_service.moc"
