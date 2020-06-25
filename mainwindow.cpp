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
	switch (id)
	{
	case ege::NO_COMPRESS:
		this->comp = ege::COMPRESSION_METHOD::NO_COMPRESS;
		break;
	case ege::LZSS:
		this->comp = ege::COMPRESSION_METHOD::LZSS;
		break;
	case ege::ZLIB_FAST:
		this->comp = ege::COMPRESSION_METHOD::ZLIB_FAST;
		break;
	case ege::ZLIB_AVERAGE:
		this->comp = ege::COMPRESSION_METHOD::ZLIB_AVERAGE;
		break;
	case ege::ZLIB_SLOW:
		this->comp = ege::COMPRESSION_METHOD::ZLIB_SLOW;
		break;
	case ege::LZO_FAST:
		this->comp = ege::COMPRESSION_METHOD::LZO_FAST;
		break;
	case ege::LZO_SLOW:
		this->comp = ege::COMPRESSION_METHOD::LZO_SLOW;
		break;
	case ege::LZ4:
		this->comp = ege::COMPRESSION_METHOD::LZ4;
		break;
	case ege::LZ4_HC:
		this->comp = ege::COMPRESSION_METHOD::LZ4_HC;
		break;
	default:
		this->comp = ege::COMPRESSION_METHOD::NO_COMPRESS;
	}
}

void MainWindow::encryptionMethod(int id)
{
	switch (id)
	{
	case ege::CRYPTO_METHOD::NO_ENCRYPT:
		this->crypt = ege::CRYPTO_METHOD::NO_ENCRYPT;
		break;
	case ege::CRYPTO_METHOD::AES:
		this->crypt = ege::CRYPTO_METHOD::AES;
		break;
	case ege::CRYPTO_METHOD::SMS4:
		this->crypt = ege::CRYPTO_METHOD::SMS4;
		break;
	case ege::CRYPTO_METHOD::RSA:
		this->crypt = ege::CRYPTO_METHOD::RSA;
		break;
	case ege::CRYPTO_METHOD::ECCP:
		this->crypt = ege::CRYPTO_METHOD::ECCP;
		break;
	default:
		this->crypt = ege::CRYPTO_METHOD::NO_ENCRYPT;
	}
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setPath(int id)
{
	QString fileName = QFileDialog::getOpenFileName(this);
	
	switch (id)
	{
	case 1:
	{
		ui->label_2->setText(fileName);
		this->pathSrc = fileName.toStdString();
		break;
	}
	case 2:
	{
		ui->label->setText(fileName);
		this->pathDest = fileName.toStdString();
		break;
	}

	}
}

