# Pideye

`/proc` dizinlerini tarayıp shell ve socket kullanımını analiz edip buna göre bir risk puanı oluşturulur.Her processin kendi özgü risk puanı oluşturulur
Yüksek puan, programın zararlı yazılım olduğu anlamına gelmiyor
 aşağıdaki kodu terminalinize kopyala-yapıştır yaparak programı kullanabilirsiniz
```bash
gcc pidsearch.c -o detector
./detector
```
Her 2 saniyede yenileniyor. Yenilemek için ENTER, çıkmak için Q + ENTER kullanabilirsiniz.
