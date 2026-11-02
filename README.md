# PurpleCreator

Panel PurpleCreator Studio z motywem czarno-fioletowym.

## Sekcje
- Połącz Hugging Face — ekran integracji i statusu (domyślnie Offline).
- Create model AI — formularz konfiguracji modelu, sprzętu i liczby przykładów.
- Czat — lista utworzonych projektów i makieta rozmowy.
- API — pusta sekcja przygotowana na później.

## Uruchomienie
Otwórz `index.html` w przeglądarce albo opublikuj repozytorium przez hosting statyczny.

## Ważne ograniczenia obecnej wersji
- Logowanie i rejestracja są tylko demonstracją interfejsu. Nie ma jeszcze prawdziwego systemu kont.
- Hugging Face OAuth nie jest jeszcze podłączony. Przycisk prowadzi do strony logowania HF, ale nie autoryzuje PurpleCreator. Status pozostaje Offline, dopóki nie powstanie backend OAuth.
- Czat jest makietą i nie łączy się jeszcze z modelem.
- Generator skryptu jest szablonem fine-tuningu. Wymaga prawdziwego ID datasetu i lokalnego logowania poleceniem `hf auth login`. Nie pobiera nieistniejącego, uniwersalnego zbioru 3 bilionów pytań i odpowiedzi.
- Limit startowy wynosi 40 000 przykładów. Możliwość treningu zależy od GPU/VRAM, RAM, modelu bazowego i danych.

## Następne wymagane prace
Do produkcyjnego uruchomienia należy dodać backend, bezpieczne konta, OAuth Hugging Face, przechowywanie projektów, endpoint czatu oraz publikację API. Nie przechowuj tokenów HF ani haseł w kodzie frontendu.
