import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Window 2.15
import QtQuick.Controls.Material 2.15 as Material
import "Theme.qml" as ThemeQml
import Qt.labs.settings 1.0

ApplicationWindow {
    id: root
    width: 1280
    height: 800
    visible: true
    title: "SysScan UI (Vulkan/C++23)"

    // Theme singleton import
    property var Theme: ThemeQml
    Material.theme: Material.Dark
    Material.accent: Theme.turquoise
    color: Theme.granite

    Settings { id: appSettings; property bool hideUncorrelatedLow: true }

    Component.onCompleted: {
        // Apply persisted preference
        appModel.setHideUncorrelatedLow(appSettings.hideUncorrelatedLow)
    }

    menuBar: MenuBar {
        Menu {
            title: qsTr("Preferences")
            MenuItem { text: qsTr("Settings..."); onTriggered: settingsDialog.open() }
            MenuItem { text: qsTr("Reload UI"); onTriggered: Qt.quit(); Qt.processEvents(); Qt.application.exec(); }
        }
        Menu {
            title: qsTr("Help")
            MenuItem { text: qsTr("About"); onTriggered: Qt.openUrlExternally("https://github.com/J-mazz/sys-scan-graph") }
        }
    }

    SplitView {
        anchors.fill: parent
        orientation: Qt.Horizontal
        
        // Handle styling
        handle: Rectangle {
            implicitWidth: 4
            color: SplitHandle.pressed ? "#007acc" : "#444444"
        }

        DashboardView {
            SplitView.preferredWidth: 800
            SplitView.minimumWidth: 500
            SplitView.fillWidth: true
        }

        ChatPanel {
            SplitView.preferredWidth: 480
            SplitView.minimumWidth: 350
        }
    }

    footer: StatusFooter { }

    // Settings dialog component
    SettingsDialog { id: settingsDialog }
}