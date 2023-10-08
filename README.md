# guardian-camera-tool
Uma ferramenta de segurança que possui a finalidade de verificar, se um ambiente residencial é seguro para instalação de câmeras.

A ferramenta tem uma interface simples, possuindo apenas 2 botões. 

O 1º botão faz o Scan da rede. Essa opção faz com que o programa encontre o endereço do gateway da rede, em outras palavras, o roteador. Após encontrar o gateway
a ferramenta irá procurar os dipositivos na rede, após consultar os endereços MAC (código único que cada dispositivo possui) que estão na tabela arp (tabela que 
mapeia os endereços mac associados a um endereço ip dentro da rede), a ferramenta filtrará esses endereços MAC para  saber se algum deles batem com os endereços 
que estão contidos no código, no caso, apenas câmeras e roteadores são considerados. Os endereços MAC são usados  para distinguir o frabicante de cada dispotivo, 
dependendo do fabricante, a forma com que interagimos com os dispositivos muda. Caso não exista nenhum dispositivo com MAC que enteja contido no código, será 
considerado não encontrado. Após identificar os dispositivos e encontrar o endereço MAC que esteja no código, o programa tentará realizar um brute force para 
ver se a senha do dispositivo é segura, caso não seja, enviará uma mensagem na tela do usuário. O programa também faz uma busca por portas conhecidas abertas, 
caso haja alguma porta desconhecida aberta, ele informa o usuário sobre o que se trata a porta e indica um link para saber mais sobre as portas. Essas portas 
foram escolhidas por serem portas comumente visadas por atacantes.

O 2º botão verifica a segurança da senha do wi-fi, primeiramente é detectado se há interface wireless na máquina, caso haja, o programa vai realizar um brute force
na rede wi-fi com o objetivo de verificar se a senha é segura, nesse processo a ferramenta captura o nome da rede wi-fi, portanto, primeiramente o usuário deve estar
conectado a uma rede wi-fi, após capturar o nome, o programa testará a conexão com as senhas padrão que estão contidas no código, nessa etapa, a conexão com a rede
wi-fi estará indisponível. Se não houver nenhuma interface wireless no dispositivo, o programa mostrará uma mensagem de erro para o usuário.
