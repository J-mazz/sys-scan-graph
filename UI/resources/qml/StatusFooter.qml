import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "Theme.qml" as ThemeQml

Rectangle {
    id: root
    height: 30
    color: ipc.connected ? ThemeQml.Theme.turquoise : ThemeQml.Theme.granite2

    RowLayout {
        anchors.fill: parent
        anchors.margins: 5

        Text {
            text: ipc.status
            color: ThemeQml.Theme.text
            font.pixelSize: 12
            font.bold: true
        }

        Item { Layout.fillWidth: true }

        BusyIndicator {
            running: !ipc.connected
            implicitHeight: 20
            implicitWidth: 20
            visible: !ipc.connected
        }
    }
}