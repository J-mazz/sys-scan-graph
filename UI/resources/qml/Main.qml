import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Window 2.15

ApplicationWindow {
    id: root
    width: 1280
    height: 800
    visible: true
    title: "SysScan UI (Vulkan/C++23)"
    color: "#121212"

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
}