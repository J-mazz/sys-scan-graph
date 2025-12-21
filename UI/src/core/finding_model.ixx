module;
#include <QAbstractListModel>
#include <vector>

export module sys_scan.ui.finding_model;

import sys_scan.ui.types;

export namespace sys_scan::ui {

    class FindingModel : public QAbstractListModel {
        Q_OBJECT

    public:
        enum Roles {
            TitleRole = Qt::UserRole + 1,
            SeverityRole,
            DescriptionRole,
            IdRole
        };

        explicit FindingModel(QObject* parent = nullptr);
        ~FindingModel();

        int rowCount(const QModelIndex& parent = QModelIndex()) const override;
        QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
        QHash<int, QByteArray> roleNames() const override;

        void loadFindings(std::vector<Finding> findings);

        Q_INVOKABLE void filterBySeverity(int minSeverity);
        Q_INVOKABLE void sortBySeverity(bool descending);

    private:
        std::vector<Finding> m_all_findings;
        std::vector<Finding> m_displayed_findings;
    };

}

// MOC generated via dedicated header (moc_includes/finding_model_moc.h)
