#include "ipc_service.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QDir>
#include <QtNetwork/QLocalSocket>
#include <QtCore/QTimer>

// Implementation of IpcService using fully qualified names

sys_scan::ui::IpcService::IpcService(QObject* parent) : QObject(parent) {
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
    
    connect(m_socket, &QLocalSocket::errorOccurred,
            this, &IpcService::handleSocketError);

    connect(m_retryTimer, &QTimer::timeout, this, [this]() {
        if (m_socket->state() != QLocalSocket::ConnectedState) {
            connectToGraph();
        }
    });

    connectToGraph();
}

sys_scan::ui::IpcService::~IpcService() = default;

bool sys_scan::ui::IpcService::isConnected() const {
    return m_socket && m_socket->state() == QLocalSocket::ConnectedState;
}

QString sys_scan::ui::IpcService::statusMessage() const {
    return m_status;
}

void sys_scan::ui::IpcService::connectToGraph() {
    if (m_socket->state() == QLocalSocket::ConnectedState) return;
    m_socket->connectToServer(QStringLiteral("/tmp/sys-scan-ui.sock"));
}

void sys_scan::ui::IpcService::handleSocketError(QLocalSocket::LocalSocketError socketError) {
    Q_UNUSED(socketError);
    m_status = QStringLiteral("Connection Error");
    emit statusChanged();
    m_retryTimer->start(2000);
}

void sys_scan::ui::IpcService::onReadyRead() {
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