#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include <QCoreApplication>
#include <QUrl>
#include <QObject>
#include <QFile>
#include <QThread>

import sys_scan.ui.report_parser;
import sys_scan.ui.finding_model;
import sys_scan.ui.types;
import sys_scan.ui.agent;
import sys_scan.ui.ipc;
#include <QProcess>

// Instantiate the model at file scope so it is accessible in signal handlers
static sys_scan::ui::FindingModel model;

int main(int argc, char *argv[]) {
    // Prefer Vulkan rendering backend when available
    QQuickWindow::setGraphicsApi(QSGRendererInterface::VulkanRhi);

    QGuiApplication app(argc, argv);

    // Application metadata
    app.setOrganizationName("MazzLabs");
    app.setApplicationName("sys-scan-ui");

    // Register types for QML access
    qmlRegisterType<sys_scan::ui::FindingModel>("SysScan.UI", 1, 0, "FindingModel");
    qRegisterMetaType<sys_scan::ui::Finding>("sys_scan::ui::Finding");

    // Initialize Model (already at file scope)



    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("appModel", &model);

    // AgentService registration & exposure
    static sys_scan::ui::AgentService agent;
    // Uncomment to preload a model when available:
    // agent.loadModel("/path/to/model.gguf");
    engine.rootContext()->setContextProperty("agentService", &agent);

    // IpcService registration & exposure
    static sys_scan::ui::IpcService ipc;
    engine.rootContext()->setContextProperty("ipc", &ipc);

    // If the IPC socket does not exist, try to launch the Agent as a subprocess
    const QString socketPath = QStringLiteral("/tmp/sys-scan-ui.sock");
    if (!QFile::exists(socketPath)) {
        // Try multiple candidate commands (best-effort)
        const QStringList candidates = {
            QStringLiteral("sys-scan-agent"),
            QStringLiteral("sys-scan-intelligence"),
            QStringLiteral("python3 -m sys_scan_agent.cli")
        };

        for (const QString &cmd : candidates) {
            // Use startDetached where possible; build arguments
            QString program = cmd;
            QStringList args;
            if (cmd == "sys-scan-agent") {
                args << QStringLiteral("--interactive") << QStringLiteral("--socket") << socketPath;
            } else if (cmd == "sys-scan-intelligence") {
                args << QStringLiteral("analyze") << QStringLiteral("--interactive") << QStringLiteral("--socket") << socketPath;
            } else { // python -m invocation
                args << QStringLiteral("-m") << QStringLiteral("sys_scan_agent.cli") << QStringLiteral("analyze") << QStringLiteral("--interactive") << QStringLiteral("--socket") << socketPath;
                program = QStringLiteral("python3");
            }

            bool started = QProcess::startDetached(program, args);
            if (started) {
                qInfo().noquote() << "Launched agent process via" << program << args.join(' ');
                break;
            }
        }

        // Wait briefly for socket to appear (non-blocking UI safe wait)
        int attempts = 0;
        while (!QFile::exists(socketPath) && attempts < 10) {
            QThread::msleep(300);
            attempts++;
        }
        if (!QFile::exists(socketPath)) {
            qWarning().noquote() << "Agent socket not found after launch attempts; UI will retry connections.";
        }
    }

    // Reload model when Python pipeline notifies of new report
    QObject::connect(&ipc, &sys_scan::ui::IpcService::analysisCompleted,
        [](QString path) {
            // Load file content and parse; guard failures silently
            QFile f(path);
            if (!f.open(QIODevice::ReadOnly)) return;
            QByteArray content = f.readAll();
            auto result = sys_scan::ui::ReportParser::parse_json(std::span(content.constData(), content.size()));
            if (std::holds_alternative<std::vector<sys_scan::ui::Finding>>(result)) {
                auto v = std::get<std::vector<sys_scan::ui::Finding>>(std::move(result));
                model.loadFindings(std::move(v));
            }
    });

    const QUrl url = QUrl::fromLocalFile(QStringLiteral("resources/qml/Main.qml"));
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
                     &app, [url](QObject *obj, const QUrl &objUrl) {
        if (!obj && url == objUrl)
            QCoreApplication::exit(-1);
    }, Qt::QueuedConnection);

    engine.load(url);

    return app.exec();
}
