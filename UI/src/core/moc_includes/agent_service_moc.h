#pragma once
#include <QObject>
#include <QString>

namespace sys_scan::ui {

class AgentService : public QObject {
    Q_OBJECT
public:
    Q_INVOKABLE bool loadModel(const QString &modelPath);
    Q_INVOKABLE void promptAsync(const QString &prompt);

Q_SIGNALS:
    void tokenReceived(QString token);
    void generationFinished();
};

} // namespace sys_scan::ui
