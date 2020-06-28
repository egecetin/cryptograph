#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

void MainWindow::srcPathClicked()
{
	this->setPath(1);
}

void MainWindow::destPathClicked()
{
	this->setPath(2);
}

void MainWindow::compressionMethod(int id)
{
	this->comp = static_cast<ege::COMPRESSION_METHOD>(id);
}

void MainWindow::encryptionMethod(int id)
{
	this->crypt = static_cast<ege::CRYPTO_METHOD>(id);
}

void MainWindow::hashMethod(int id)
{
	this->hash = static_cast<IppHashAlgId>(id);
}

void MainWindow::convert()
{
	ERR_STATUS status = NO_ERROR;
	
	// Check files

	// Ask for password
	bool flag = false;
	while (!flag)
	{
		QString text = QInputDialog::getText(this, tr("QInputDialog::getText()"), tr("Password:"), QLineEdit::Password, QString(), &flag);
		if (text.isEmpty()) {
			QMessageBox::critical(this, tr("Error"), tr("Password can't be empty!"));
			flag = false;
		}			
		else if (text.length() > 32) {
			QMessageBox::critical(this, tr("Error"), tr("Password can't be longer than 32 character"));
			flag = false;
		}			
	}
	
	// Check password

	// pack/unpack

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setPath(int id)
{
	QString fileName;	
	
	switch (id)
	{
	case 1:
	{
		fileName = QFileDialog::getOpenFileName(this);
		ui->label_2->setText(fileName);
		this->pathSrc = fileName.toStdString();
		break;
	}
	case 2:
	{
		fileName = QFileDialog::getSaveFileName(this, tr("Select save location"), this->pathSrc.c_str(), tr("Encrypted file (*.ege)"));
		ui->label->setText(fileName);
		this->pathDest = fileName.toStdString();
		break;
	}
	}
}

