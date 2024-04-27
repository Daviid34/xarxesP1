Els arguments per l'execució dels programes són els indicats en l'enunciat de la pràctica.
El port UDP per enviar els SUBS_REQ és el 2002 (com es pot veure en tots els arxius de configuració).
Finalment, cal esmentar que una vegada de cada moltíssimes hi ha un bug on, si executes les dues implementacions entre si alhora es queda el servidor en l'estat wait_info i el client en l'estat wait_ack_info. Si es tanquen els dos programes i es tornen a executar aquest error desapareix.
