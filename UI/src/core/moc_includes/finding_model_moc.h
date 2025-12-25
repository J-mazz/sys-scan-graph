#pragma once
#include <QAbstractListModel>

namespace sys_scan::ui {

class FindingModel : public QAbstractListModel {
    Q_OBJECT
public:
    Q_INVOKABLE void filterBySeverity(int minSeverity);
    Q_INVOKABLE void sortBySeverity(bool descending);
};

} // namespace sys_scan::ui
