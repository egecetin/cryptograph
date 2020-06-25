#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "filer.h"

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
	void srcPathClicked();
	void destPathClicked();
	void compressionMethod(int id);
	void encryptionMethod(int id);
	void convert();
    ~MainWindow();

private:
    Ui::MainWindow *ui;
	std::string pathSrc, pathDest;
	ege::COMPRESSION_METHOD comp;
	ege::CRYPTO_METHOD crypt;

	void setPath(int id);

};
#endif // MAINWINDOW_H
