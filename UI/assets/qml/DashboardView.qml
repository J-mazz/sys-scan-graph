import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Page {
    id: root

    header: ToolBar {
        RowLayout {
            anchors.fill: parent
            Label {
                text: "Security Dashboard"
                font.pixelSize: 20
                Layout.leftMargin: 20
            }
            Item { Layout.fillWidth: true }
            ComboBox {
                model: ["All", "Low+", "Medium+", "High+", "Critical"]
                onActivated: (index) => {
                    // map index to severity (0..4)
                    appModel.filterBySeverity(index)
                }
            }
        }
    }

    ListView {
        id: findingList
        anchors.fill: parent
        anchors.margins: 20
        spacing: 10
        model: appModel

        delegate: Rectangle {
            width: findingList.width
            height: 60
            color: "#2b2b2b"
            radius: 5
            border.color: "#3f3f3f"

            RowLayout {
                anchors.fill: parent
                anchors.margins: 10

                Rectangle {
                    width: 16; height: 16; radius: 8
                    color: model.severity === 4 ? "#ff4444" : (model.severity === 3 ? "#ff8800" : "#44ff44")
                }

                ColumnLayout {
                    Label {
                        text: model.title
                        font.bold: true
                        color: "#ffffff"
                    }
                    Label {
                        text: model.description
                        font.pixelSize: 12
                        color: "#aaaaaa"
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }
                }
            }
        }
    }
}
