#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
	ege::Filer abcd, dcba;
	Ipp8u key[32] = "1234567890123456789012345678901";
	char path1[] = ".\\deneme_in.txt";
	char path2[] = ".\\deneme_dest.txt";
	char path3[] = ".\\deneme_dest2.txt";
	//char path1[] = "C:\\Users\\egece\\Videos\\Ace Combat 7 _ Skies Unknown - Movie Cutscenes.mp4";
	//char path2[] = "C:\\Users\\egece\\Videos\\Ace Combat 7 _ Skies Unknown - Movie Cutscenes_enc.ege";
	//char path3[] = "C:\\Users\\egece\\Videos\\Ace Combat 7 _ Skies Unknown - Movie Cutscenes_rec.mp4";
	abcd.setKey(key, 32);
	abcd.setPath(path1);
	abcd.setCompressionType(ege::LZ4);
	abcd.setEncryptionMethod(ege::AES);
	abcd.setHashMethod(ippHashAlg_SHA512);
	abcd.pack(path2, true);

	dcba.setPath(path2);
	dcba.setKey(key, 32);
	dcba.unpack(path3, true);


    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
