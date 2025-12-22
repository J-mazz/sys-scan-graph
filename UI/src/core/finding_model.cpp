#include "finding_model.h"
#include <vector>
#include <QString>
#include <memory>
#include <algorithm>

import sys_scan.ui.types; // ensure canonical module type for Finding

// Define the PIMPL struct in the same namespace as the header declaration
struct sys_scan::ui::FindingModelImpl {
    std::vector<sys_scan::ui::Finding> findings;
};

sys_scan::ui::FindingModel::FindingModel(QObject* parent)
    : QAbstractListModel(parent), m_impl(std::make_unique<sys_scan::ui::FindingModelImpl>()) {}

sys_scan::ui::FindingModel::~FindingModel() = default;

int sys_scan::ui::FindingModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return static_cast<int>(m_impl->findings.size());
}

QVariant sys_scan::ui::FindingModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= m_impl->findings.size())
        return QVariant();

    const auto& finding = m_impl->findings[index.row()];
    switch (role) {
        case IdRole: return finding.id;
        case TitleRole: return finding.title;
        case SeverityRole: return finding.severity;
        case DescriptionRole: return finding.description;
    }
    return QVariant();
}

QHash<int, QByteArray> sys_scan::ui::FindingModel::roleNames() const {
    return {
        {IdRole, "id"},
        {TitleRole, "title"},
        {SeverityRole, "severity"},
        {DescriptionRole, "description"}
    };
}

void sys_scan::ui::FindingModel::clear() {
    beginResetModel();
    m_impl->findings.clear();
    endResetModel();
}

void sys_scan::ui::FindingModel::loadFindings(std::vector<Finding> findings) {
    beginResetModel();
    m_impl->findings = std::move(findings);
    endResetModel();
}

void sys_scan::ui::FindingModel::filterBySeverity(int minSeverity) {
    beginResetModel();
    auto& vec = m_impl->findings;
    vec.erase(std::remove_if(vec.begin(), vec.end(), [minSeverity](const Finding& f) {
        return static_cast<int>(f.severity) < minSeverity;
    }), vec.end());
    endResetModel();
}

void sys_scan::ui::FindingModel::sortBySeverity(bool descending) {
    beginResetModel();
    auto& vec = m_impl->findings;
    std::sort(vec.begin(), vec.end(), [descending](const Finding& a, const Finding& b) {
        if (descending)
            return static_cast<int>(a.severity) > static_cast<int>(b.severity);
        return static_cast<int>(a.severity) < static_cast<int>(b.severity);
    });
    endResetModel();
}