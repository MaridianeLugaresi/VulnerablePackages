<H2>Vulnerabilides em Pacotes da Rede</H2>

<p>
No decorrer dos estudos da disciplina de Redes de Computadores, tivemos a oportunidade de identificar que comumente todos os protocolos de comunicação possuem vulnerabilidades conhecidas e alguns já em desuso. Com isso, o objetivo deste projeto é realizar a leitura e interpretação de arquivos previamente capturados pelo Wireshark, sendo este um software de sniffer. Após a interpretação dos pacotes, realizada pela biblioteca pyshark, é realizado filtro pelos pacotes HTTP e FTP em especifico, visto que ambos trafegam dados sem criptografia e portanto aumentam a vulnerabilidade dos sistemas que o utilizam.
</p>

<p>
Para cada um dos protocolos foram implementadom comportamentos especificos para manipular os dados:
</p>

<ul>
    <li>HTTP: utilizado regex para pesquisar por strings como usuário e senha </li>
    <li>FTP: utilizado regex para pesquisar por padrões de e-mails </li>
</ul>

<p>
No decorrer da manipulação dos dados são realizados prints das informações na linha de comando e ao finalizar a execução de leitura será gerado um dashboard com a volumetria de pacotes encontrados com vulnerabilidade, separados por tipo de protocolo, habilitando a possibilidade de clicar no gráfico e listar dados dos pacotes relacionados.
</p>
