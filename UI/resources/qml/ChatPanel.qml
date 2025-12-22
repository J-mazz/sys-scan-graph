import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    color: Theme.slate
    anchors.fill: parent

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 10

        // Refinement: Wrap in ScrollView for auto-scrolling
        ScrollView {
            id: scrollView
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            TextArea {
                id: chatOutput
                readOnly: true
                color: Theme.text
                selectionColor: Theme.turquoise
                selectedTextColor: "#000000"
                selectByMouse: true
                textFormat: TextEdit.MarkdownText // Enable bold/bullets from LLM
                
                background: Rectangle { 
                    color: Theme.granite2
                    radius: 4 
                }
                font.pixelSize: 14
                wrapMode: Text.Wrap
            }
        }

        RowLayout {
            Layout.fillWidth: true
            height: 40

            TextField {
                id: chatInput
                Layout.fillWidth: true
                placeholderText: "Ask the Agent (e.g., 'Analyze critical risks')..."
                color: Theme.text
                background: Rectangle {
                    color: Theme.granite2
                    radius: 4
                    border.color: chatInput.activeFocus ? Theme.turquoise : Theme.granite2
                }
                onAccepted: sendBtn.clicked()
            }

            Button {
                id: sendBtn
                text: "Send"
                background: Rectangle { color: Theme.turquoise; radius: 4 }
                onClicked: {
                    if (chatInput.text.trim() === "") return;
                    
                    // formatting input
                    chatOutput.append("\n**You:** " + chatInput.text);
                    chatOutput.append("**Agent:** ");

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
            // Auto-scroll logic
            if (chatOutput.cursorPosition < chatOutput.length)
                chatOutput.cursorPosition = chatOutput.length;
        }
        function onGenerationFinished() {
            chatOutput.append("\n");
        }
    }
}