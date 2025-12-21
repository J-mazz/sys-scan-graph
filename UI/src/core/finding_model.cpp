module;
#include <QVariant>
#include <QHash>
#include <ranges>
#include <algorithm>

module sys_scan.ui.finding_model;

import sys_scan.ui.types;

namespace sys_scan::ui {

    FindingModel::FindingModel(QObject* parent) : QAbstractListModel(parent) {}
    FindingModel::~FindingModel() = default;

    int FindingModel::rowCount(const QModelIndex& parent) const {
        Q_UNUSED(parent);
        return static_cast<int>(m_displayed_findings.size());
    }

    QVariant FindingModel::data(const QModelIndex& index, int role) const {
        if (!index.isValid() || index.row() >= static_cast<int>(m_displayed_findings.size()))
            return {};

        const auto& finding = m_displayed_findings[static_cast<size_t>(index.row())];

        switch (role) {
            case TitleRole: return finding.title;
            case SeverityRole: return QVariant::fromValue(static_cast<int>(finding.severity));
            case DescriptionRole: return finding.description;
            case IdRole: return finding.id;
            default: return {};
        }
    }

    QHash<int, QByteArray> FindingModel::roleNames() const {
        return {
            {TitleRole, "title"},
            {SeverityRole, "severity"},
            {DescriptionRole, "description"},
            {IdRole, "id"}
        };
    }

    void FindingModel::loadFindings(std::vector<Finding> findings) {
        beginResetModel();
        m_all_findings = std::move(findings);
        m_displayed_findings = m_all_findings;
        endResetModel();
    }

    void FindingModel::filterBySeverity(int minSeverity) {
        beginResetModel();
        auto filter_view = m_all_findings |
            std::views::filter([minSeverity](const Finding& f) {
                return static_cast<int>(f.severity) >= minSeverity;
            });

        m_displayed_findings.clear();
        std::ranges::copy(filter_view, std::back_inserter(m_displayed_findings));
        endResetModel();
    }

    void FindingModel::sortBySeverity(bool descending) {
        layoutAboutToBeChanged();
        if (descending) {
            std::ranges::sort(m_displayed_findings, std::greater<>{}, &Finding::severity);
        } else {
            std::ranges::sort(m_displayed_findings, std::less<>{}, &Finding::severity);
        }
        layoutChanged();
    }

} // namespace sys_scan::ui


