import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Page {
    id: root
    background: Rectangle { color: "#252525" } // Dark background

    header: ToolBar {
        background: Rectangle { color: Theme.granite2 }
        RowLayout {
            anchors.fill: parent
            anchors.margins: 5
            
            Label {
                text: "Security Dashboard"
                font.pixelSize: 18
                font.bold: true
                color: Theme.text
                Layout.leftMargin: 10
            }
            
            Item { Layout.fillWidth: true }
            
            Label { text: "Min Severity:"; color: Theme.muted }
            ComboBox {
                id: severityCombo
                model: ["All", "Low", "Medium", "High", "Critical"]
                currentIndex: 0
                Layout.preferredWidth: 120
                onActivated: (index) => {
                    appModel.filterBySeverity(index)
                }
            }

            Label { text: "Sort:"; color: Theme.muted; Layout.leftMargin: 8 }
            ComboBox {
                id: sortCombo
                model: ["Severity (desc)", "Severity (asc)", "Title"]
                currentIndex: 0
                Layout.preferredWidth: 140
                onActivated: (i) => {
                    if (i === 0) appModel.sortBySeverity(true);
                    else if (i === 1) appModel.sortBySeverity(false);
                    else appModel.applyFilters();
                }
            }

            CheckBox {
                id: hideUncorr
                text: "Hide low/info unless correlated"
                checked: false
                onCheckedChanged: appModel.setHideUncorrelatedLow(checked)
            }
        }
    }

    ListView {
        id: findingList
        anchors.fill: parent
        anchors.margins: 20
        spacing: 8
        model: appModel
        clip: true

        delegate: Rectangle {
            width: findingList.width
            height: 70
            color: "#2b2b2b"
            radius: 4
            border.color: "#3f3f3f"
            border.width: 1

            RowLayout {
                anchors.fill: parent
                anchors.margins: 12
                spacing: 15

                // Severity Indicator
                Rectangle {
                    width: 12
                    height: 12
                    radius: 6
                    // Map C++ severity (1-4) to colors
                    color: {
                        if (model.severity >= 4) return "#ff4444" // Critical
                        if (model.severity === 3) return "#ff8800" // High
                        if (model.severity === 2) return "#ffcc00" // Medium
                        return "#44ff44" // Low
                    }
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4
                    
                    Label {
                        text: model.title
                        font.bold: true
                        font.pixelSize: 15
                        color: "#ffffff"
                    }
                    
                    Label {
                        text: model.description
                        font.pixelSize: 13
                        color: "#aaaaaa"
                        elide: Text.ElideRight
                        maximumLineCount: 1
                        Layout.fillWidth: true
                    }
                }
                
                // Optional: Arrow icon or severity text
                Label {
                    text: ["?", "LOW", "MED", "HIGH", "CRIT"][Math.min(model.severity, 4)]
                    color: "#555555"
                    font.pixelSize: 10
                    font.bold: true
                }
            }
        }
        
        // ScrollBar for the list
        ScrollBar.vertical: ScrollBar { }
    }
}