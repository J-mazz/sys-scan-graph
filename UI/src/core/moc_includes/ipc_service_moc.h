#pragma once
#include <QObject>
#include <QString>

namespace sys_scan::ui {

class IpcService : public QObject {
    Q_OBJECT
public:
    Q_INVOKABLE void connectToGraph();
    Q_INVOKABLE bool isConnected() const;
    Q_INVOKABLE QString statusMessage() const;

Q_SIGNALS:
    void connectionChanged();
    void statusChanged();
    void analysisCompleted(QString reportPath);
};

} // namespace sys_scan::ui
