module;
#include <QObject>
#include <QString>
#include <string>

export module sys_scan.ui.agent;

import sys_scan.ui.coro;

export namespace sys_scan::ui {

    class AgentService : public QObject {
        Q_OBJECT
    public:
        explicit AgentService(QObject* parent = nullptr);
        ~AgentService();

        Q_INVOKABLE bool loadModel(const QString& modelPath);

        Generator<QString> ask(std::string prompt);

        Q_SIGNAL void tokenReceived(QString token);
        Q_SIGNAL void generationFinished();

        Q_INVOKABLE void promptAsync(const QString& prompt);

    private:
        struct Impl;
        Impl* m_impl;
    };
}

// Ensure moc symbols for Q_OBJECT in the interface are generated
#include "moc_agent_service.moc"