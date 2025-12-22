#include "finding_model.h"
#include <vector>
#include <QString>
#include <memory>
#include <algorithm>

import sys_scan.ui.types; // ensure canonical module type for Finding

// Define the PIMPL struct in the same namespace as the header declaration
struct sys_scan::ui::FindingModelImpl {
    std::vector<sys_scan::ui::Finding> all_findings;
    std::vector<sys_scan::ui::Finding> visible_findings;
    int min_severity_filter{0};
    bool hide_uncorrelated_low{false};
};

sys_scan::ui::FindingModel::FindingModel(QObject* parent)
    : QAbstractListModel(parent), m_impl(std::make_unique<sys_scan::ui::FindingModelImpl>()) {}

sys_scan::ui::FindingModel::~FindingModel() = default;

int sys_scan::ui::FindingModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return static_cast<int>(m_impl->visible_findings.size());
}

QVariant sys_scan::ui::FindingModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= m_impl->visible_findings.size())
        return QVariant();

    const auto& finding = m_impl->visible_findings[index.row()];
    switch (role) {
        case IdRole: return finding.id;
        case TitleRole: return finding.title;
        case SeverityRole: return static_cast<int>(finding.severity);
        case DescriptionRole: return finding.description;
        case CorrelatedRole: return finding.correlated;
    }
    return QVariant();
}

QHash<int, QByteArray> sys_scan::ui::FindingModel::roleNames() const {
    return {
        {IdRole, "id"},
        {TitleRole, "title"},
        {SeverityRole, "severity"},
        {DescriptionRole, "description"},
        {CorrelatedRole, "correlated"}
    };
}

void sys_scan::ui::FindingModel::clear() {
    beginResetModel();
    m_impl->all_findings.clear();
    m_impl->visible_findings.clear();
    endResetModel();
}

void sys_scan::ui::FindingModel::loadFindings(std::vector<Finding> findings) {
    beginResetModel();
    m_impl->all_findings = std::move(findings);
    // Initially visible is the full list
    m_impl->visible_findings = m_impl->all_findings;
    endResetModel();
}

void sys_scan::ui::FindingModel::filterBySeverity(int minSeverity) {
    m_impl->min_severity_filter = minSeverity;
    applyFilters();
}

void sys_scan::ui::FindingModel::setHideUncorrelatedLow(bool hide) {
    m_impl->hide_uncorrelated_low = hide;
    applyFilters();
}

void sys_scan::ui::FindingModel::applyFilters() {
    beginResetModel();
    m_impl->visible_findings.clear();
    for (const auto& f : m_impl->all_findings) {
        if (static_cast<int>(f.severity) < m_impl->min_severity_filter) continue;
        if (m_impl->hide_uncorrelated_low) {
            if ((f.severity == Severity::Info || f.severity == Severity::Low) && !f.correlated) continue;
        }
        m_impl->visible_findings.push_back(f);
    }
    endResetModel();
}

void sys_scan::ui::FindingModel::sortBySeverity(bool descending) {
    beginResetModel();
    auto& vec = m_impl->visible_findings;
    std::sort(vec.begin(), vec.end(), [descending](const Finding& a, const Finding& b) {
        if (descending)
            return static_cast<int>(a.severity) > static_cast<int>(b.severity);
        return static_cast<int>(a.severity) < static_cast<int>(b.severity);
    });
    endResetModel();
}