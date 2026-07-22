//
// Created by Tofu on 2025/10/11.
//

#ifndef DWRGFPSUNLOCKER_TRAY_H
#define DWRGFPSUNLOCKER_TRAY_H

#if !defined(CI)
#include "storage.h"
#endif

#include <QMenu>
#include <QSystemTrayIcon>

class AppTray:public QSystemTrayIcon
{
    QMenu *traymenu;
public:
    AppTray(QObject* parent = nullptr):QSystemTrayIcon(parent)
    {
        setIcon(QIcon(":/纯彩mini.ico"));
        traymenu = new QMenu();
        traymenu->addAction("重置", &Storage<hipp,"hipp">::clear);
        traymenu->addAction("退出", &QApplication::quit);
        setContextMenu(traymenu);
    }
    ~AppTray() override
    {
        delete traymenu;
    }
};

#endif //DWRGFPSUNLOCKER_TRAY_H