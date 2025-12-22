import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    color: "#1e1e1e"
    anchors.fill: parent

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 10

        TextArea {
            id: chatOutput
            Layout.fillHeight: true
            Layout.fillWidth: true
            readOnly: true
            color: "#e0e0e0"
            background: Rectangle { color: "#2d2d2d"; radius: 4 }
            font.pixelSize: 14
            wrapMode: Text.Wrap
        }

        RowLayout {
            Layout.fillWidth: true
            height: 40

            TextField {
                id: chatInput
                Layout.fillWidth: true
                placeholderText: "Ask the Agent (e.g., 'Analyze critical risks')..."
                onAccepted: sendBtn.clicked()
            }

            Button {
                id: sendBtn
                text: "Send"
                onClicked: {
                    if (chatInput.text === "") return;
                    chatOutput.append("\n> " + chatInput.text);
                    chatOutput.append("Agent: ");

                    agentService.promptAsync(chatInput.text);
                    chatInput.text = "";
                }
            }
        }
    }

    Connections {
        target: agentService
        function onTokenReceived(token) {
            chatOutput.insert(chatOutput.length, token);
        }
        function onGenerationFinished() {
            chatOutput.append("\n");
        }
    }
}
