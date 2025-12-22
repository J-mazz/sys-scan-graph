#pragma once

#include <QObject>
#include <QString>
#include <memory>
#include <QtQml/qqml.h>

namespace sys_scan::ui {

struct AgentServiceImpl; // namespace-scope PIMPL forward declaration

class AgentService : public QObject {
    Q_OBJECT
    QML_ELEMENT
public:
    explicit AgentService(QObject* parent = nullptr);
    ~AgentService();

    Q_INVOKABLE bool loadModel(const QString& modelPath);
    Q_INVOKABLE void promptAsync(const QString& prompt);

signals:
    void tokenReceived(QString token);
    void generationFinished();

private:
    AgentServiceImpl* m_impl{nullptr};
};

} // namespace sys_scan::ui