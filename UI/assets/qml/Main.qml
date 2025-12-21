import QtQuick 2.15
import QtQuick.Controls 2.15

ApplicationWindow {
    id: root
    width: 1280
    height: 720
    visible: true
    title: "SysScan UI (Vulkan)"

    SplitView {
        anchors.fill: parent
        orientation: Qt.Horizontal

        DashboardView {
            SplitView.preferredWidth: 800
            SplitView.minimumWidth: 400
        }

        ChatPanel {
            SplitView.preferredWidth: 480
            SplitView.minimumWidth: 300
        }
    }

    footer: StatusFooter { }
}
