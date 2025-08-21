# Analizator Bezpieczeństwa PDF

Prosta aplikacja webowa do analizy bezpieczeństwa plików PDF, która pomaga wykrywać potencjalnie niebezpieczne elementy w dokumentach PDF.

## Funkcje

- Analiza plików PDF pod kątem zagrożeń bezpieczeństwa
- Wykrywanie niebezpiecznych elementów (JavaScript, automatyczne akcje, osadzone pliki)
- Identyfikacja i analiza linków zawartych w dokumentach
- Podgląd pierwszych 3 stron dokumentu (dla bezpiecznych plików)
- Bezpieczne usuwanie przesłanych plików po analizie

## Wymagania

- Python 3.7+
- Flask
- PyMuPDF (fitz)
- Pillow
- Flask-Talisman
- Flask-Limiter
- PDFiD

## Instalacja

1. Sklonuj repozytorium lub pobierz pliki projektu
2. Zainstaluj wymagane pakiety:

```bash
pip install flask flask-talisman flask-limiter Pillow PyMuPDF
```

3. Zainstaluj PDFiD zgodnie z instrukcją na [stronie projektu](https://blog.didierstevens.com/programs/pdf-tools/)

## Uruchomienie

Uruchom aplikację za pomocą:

```bash
python app.py
```

Aplikacja będzie dostępna pod adresem: http://localhost:5000

## Korzystanie z aplikacji

1. Otwórz stronę aplikacji w przeglądarce
2. Przeciągnij plik PDF na wskazany obszar lub kliknij przycisk "Wybierz plik"
3. Poczekaj na wyniki analizy
4. Przejrzyj wyniki oraz ostrzeżenia
5. Dla bezpiecznych plików można wyświetlić podgląd pierwszych 3 stron

## Bezpieczeństwo

Aplikacja została zaprojektowana z myślą o bezpieczeństwie:
- Przesłane pliki są bezpiecznie usuwane po analizie
- Podgląd dokumentów jest generowany tylko dla bezpiecznych plików
- Aplikacja identyfikuje podejrzane linki i ostrzega użytkownika

## Jak to działa

### Analiza bezpieczeństwa

Proces analizy bezpieczeństwa plików PDF przebiega wieloetapowo:

1. **Wstępna analiza metadanych**:
   - Aplikacja wykorzystuje narzędzie PDFiD do analizy struktury pliku PDF bez wykonywania jego kodu
   - Sprawdzane są najbardziej niebezpieczne elementy (JavaScript, akcje automatyczne, uruchamianie programów)
   - Na podstawie metadanych podejmowana jest decyzja czy plik jest bezpieczny do dalszej analizy

2. **Ocena poziomu ryzyka**:
   - Każdy niebezpieczny element otrzymuje punktację ryzyka
   - Na podstawie sumy punktów dokument jest klasyfikowany jako:
     - Bezpieczny (SAFE)
     - Niskiego ryzyka (LOW_RISK)
     - Średniego ryzyka (MEDIUM_RISK)
     - Wysokiego ryzyka (HIGH_RISK)

3. **Analiza linków**:
   - Z bezpiecznych plików ekstrahowane są wszystkie linki (aktywne i zawarte w tekście)
   - Każdy link jest analizowany pod kątem potencjalnego ryzyka:
     - Wykrywanie skróconych URLi
     - Sprawdzanie nieszyfrowanych połączeń (http://)
     - Identyfikacja nietypowych domen
     - Wykrywanie adresów IP zamiast nazw domen

4. **Generowanie podglądu**:
   - Podgląd generowany jest wyłącznie dla plików, które nie zawierają niebezpiecznych elementów
   - Pierwsze 3 strony dokumentu są renderowane jako statyczne obrazy PNG
   - Interaktywne elementy nie są aktywne w podglądzie

### Bezpieczeństwo danych

1. **Zabezpieczenie przesyłanych plików**:
   - Każdy przesłany plik otrzymuje unikalny identyfikator UUID
   - Pliki są zapisywane w tymczasowym folderze z bezpiecznymi nazwami
   - Po analizie pliki są bezpiecznie usuwane (trzykrotne nadpisanie danych przed usunięciem)

2. **Ochrona przed atakami**:
   - Aplikacja używa Flask-Talisman do wymuszania bezpiecznych nagłówków HTTP
   - Zastosowano limitowanie liczby zapytań (10 na minutę) dla ochrony przed atakami DoS
   - Content Security Policy ogranicza wykonywanie skryptów zewnętrznych

3. **Izolacja niebezpiecznych plików**:
   - Pliki zawierające JavaScript, akcje automatyczne lub osadzone pliki są traktowane jako potencjalnie złośliwe
   - Dla takich plików nie jest generowany podgląd, co minimalizuje ryzyko uruchomienia złośliwego kodu

### Schemat przepływu danych

1. Użytkownik przesyła plik PDF poprzez interfejs webowy
2. Backend przyjmuje plik i zapisuje go tymczasowo z unikalną nazwą
3. Wykonywana jest analiza bezpieczeństwa metadanych
4. Jeśli plik jest bezpieczny, przeprowadzana jest dalsza analiza linków
5. Wyniki analizy są zwracane do interfejsu użytkownika
6. Przesłany plik jest bezpiecznie usuwany z serwera
7. Użytkownik może opcjonalnie wyświetlić podgląd bezpiecznego pliku

### Ograniczenia

- Analiza opiera się głównie na statycznych metadanych i może nie wykryć wszystkich zagrożeń
- Ukryte lub zaszyfrowane złośliwe elementy mogą nie zostać wykryte
- Pliki większe niż 16MB nie są obsługiwane ze względów bezpieczeństwa
