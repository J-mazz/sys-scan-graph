#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include <QCoreApplication>
#include <QUrl>
#include <QObject>
#include <QFile>
#include <QThread>

#include "core/report_parser.h"
#include "core/finding_model.h"
#include "core/types.h"
#include "core/agent_service.h"
#include "core/ipc_service.h"
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
    qmlRegisterSingletonType(QUrl("qrc:/Theme.qml"), "SysScan.UI", 1, 0, "Theme");

    // Initialize Model (already at file scope)



    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("appModel", &model);

    // AgentService registration & exposure
    static sys_scan::ui::AgentService agent;
    engine.rootContext()->setContextProperty("agentService", &agent);

    // IpcService registration & exposure
    static sys_scan::ui::IpcService ipc;
    engine.rootContext()->setContextProperty("ipc", &ipc);

    // If the IPC socket does not exist, try to launch the Agent as a subprocess
    // Use canonical agent entrypoints to avoid shipping demo/legacy names or commented toggles.
    const QString socketPath = QStringLiteral("/tmp/sys-scan-ui.sock");
    if (!QFile::exists(socketPath)) {
        // Try a minimal, canonical set of commands (best-effort) — prefer the packaged Python entrypoint
        const QStringList candidates = {
            // Prefer the top-level CLI package which is the canonical entrypoint for interactive runs
            QStringLiteral("sys-scan-graph"),
            // Fallback to invoking the Python module directly if the package isn't on PATH
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

    // Resolve Main QML file from multiple candidate locations so the UI works
    // when run from build dir, installed paths, or when assets are packaged.
    const QStringList qmlCandidates = {
        QStringLiteral("resources/qml/Main.qml"),
        QCoreApplication::applicationDirPath() + QStringLiteral("/resources/qml/Main.qml"),
        QCoreApplication::applicationDirPath() + QStringLiteral("/../resources/qml/Main.qml"),
        QCoreApplication::applicationDirPath() + QStringLiteral("/../assets/qml/Main.qml"),
        QStringLiteral("assets/qml/Main.qml")
    };

    QString qmlPath;
    for (const QString &c : qmlCandidates) {
        if (QFile::exists(c)) { qmlPath = c; break; }
    }
    if (qmlPath.isEmpty()) {
        qWarning().noquote() << "Main QML not found; tried:" << qmlCandidates;
        qmlPath = QStringLiteral("resources/qml/Main.qml"); // fallback to original path
    }

    const QUrl url = QUrl::fromLocalFile(qmlPath);
    qInfo().noquote() << "Loading QML from" << url.toString();

    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
                     &app, [url](QObject *obj, const QUrl &objUrl) {
        if (!obj && url == objUrl)
            QCoreApplication::exit(-1);
    }, Qt::QueuedConnection);

    engine.load(url);

    return app.exec();
}
