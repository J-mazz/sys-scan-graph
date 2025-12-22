import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    id: root
    height: 30
    color: ipc.isConnected ? "#007acc" : "#cc3300"

    RowLayout {
        anchors.fill: parent
        anchors.margins: 5

        Text {
            text: ipc.statusMessage
            color: "white"
            font.pixelSize: 12
            font.bold: true
        }

        Item { Layout.fillWidth: true }

        BusyIndicator {
            running: !ipc.isConnected
            implicitHeight: 20
            implicitWidth: 20
            visible: !ipc.isConnected
        }
    }
}
