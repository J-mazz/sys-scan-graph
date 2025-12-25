#pragma once

#include <QObject>
#include <QString>
#include <QtQml/qqml.h>
#include <QLocalSocket>
#include <QTimer>

namespace sys_scan::ui {

struct IpcServiceImpl; // namespace-scope PIMPL forward declaration

class IpcService : public QObject {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(bool connected READ isConnected NOTIFY connectionChanged)
    Q_PROPERTY(QString status READ statusMessage NOTIFY statusChanged)

public:
    explicit IpcService(QObject* parent = nullptr);
    ~IpcService();

    bool isConnected() const;
    QString statusMessage() const;

    Q_INVOKABLE void connectToGraph();

signals:
    void connectionChanged();
    void statusChanged();
    void analysisCompleted(QString reportPath);

private slots:
    void onReadyRead();
    void handleSocketError(QLocalSocket::LocalSocketError socketError);

private:
    QLocalSocket* m_socket = nullptr;
    QTimer* m_retryTimer = nullptr;
    QString m_status;
};

} // namespace sys_scan::ui