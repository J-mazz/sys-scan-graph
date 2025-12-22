import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: settingsDialog
    title: qsTr("Settings")
    modal: true
    standardButtons: Dialog.Ok | Dialog.Cancel

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 8

        Label { text: qsTr("Appearance") ; font.bold: true }
        RowLayout {
            Label { text: qsTr("Theme") }
            ComboBox { model: ["Granite/Turquoise"] }
        }

        Label { text: qsTr("Behavior") ; font.bold: true }
        CheckBox { id: cbHideUncorrelatedLow; text: qsTr("Hide Info/Low unless correlated"); checked: appSettings.hideUncorrelatedLow; onCheckedChanged: { appSettings.hideUncorrelatedLow = checked; appModel.setHideUncorrelatedLow(checked); } }

        Label { text: qsTr("Agent") ; font.bold: true }
        RowLayout {
            Label { text: qsTr("Streaming Mode") }
            ComboBox { model: ["local", "external (langchain)"] }
        }
    }

    onAccepted: settingsDialog.close()
}
