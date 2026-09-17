# Pideye

`/proc` dizinlerini tarayıp shell, socket ve TCP davranışlarını analiz edip risk puanı oluşturuluyor. Her processin kendi özgü risk puanı oluşturulur
Yüksek puan, sürecin zararlı yazılım olduğu anlamına gelmiyor
 aşağıdaki kodu terminalinize kopyala yapıştır yaparak programı kullanabilirsiniz
```bash
gcc pidsearch.c -o detector
./detector
```

Her 2 saniyede yenileniyor. Yenilemek için ENTER, çıkmak için Q + ENTER kullanabilirsiniz.
