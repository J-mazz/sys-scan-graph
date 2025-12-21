module;
#include <QObject>
#include <QLocalSocket>
#include <QString>
#include <QTimer>

export module sys_scan.ui.ipc;

export namespace sys_scan::ui {

    class IpcService : public QObject {
        Q_OBJECT
        Q_PROPERTY(bool isConnected READ isConnected NOTIFY connectionChanged)
        Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusChanged)

    public:
        explicit IpcService(QObject* parent = nullptr);

        bool isConnected() const;
        QString statusMessage() const;

        Q_INVOKABLE void connectToGraph();

    signals:
        void connectionChanged();
        void statusChanged();
        void analysisCompleted(QString reportPath);

    private:
        void onReadyRead();
        void onError(QLocalSocket::LocalSocketError socketError);

        QLocalSocket* m_socket{};
        QString m_status;
        QTimer* m_retryTimer{};
    };
}

// Ensure moc symbols for Q_OBJECT in the interface are generated
#include "moc_ipc_service.moc"
