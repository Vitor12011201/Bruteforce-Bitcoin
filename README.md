# bip39-bruteforce-lab

Laboratório local em Python 3.11+ para estudar BIP-39: validar uma mnemonic
completa fornecida pelo usuário ou recuperar **somente uma a onze palavras
desconhecidas de uma mnemonic de laboratório**, comparando cada candidato válido
com um único endereço definido pelo usuário.

Opcionalmente, é possível acompanhar o saldo confirmado desse endereço-alvo em
um nó Bitcoin Core **local, em regtest**, enquanto a busca continua.

**NUNCA envie dinheiro real para estes endereços. Não reutilize as mnemonics,
seeds ou chaves do laboratório em carteiras reais.** Os exemplos e vetores de
teste são públicos e previsíveis.

## Instalação

O projeto ocupa a raiz deste diretório; não é necessário criar outra pasta.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py --help
```

Pode usar outro Python 3.11+, desde que as dependências suportem sua versão.
Esta implementação foi validada com Python 3.11.15. A instalação baixa pacotes;
depois disso, os comandos e testes padrão funcionam offline, sem nó Bitcoin.
Somente o monitor opcional de saldo exige um nó Bitcoin Core local em regtest.
Essa integração usa a biblioteca padrão do Python, sem nova dependência pip.

Dependências diretas fixadas:

- `mnemonic==0.21`: implementação de referência da Trezor, wordlist English,
  geração com aleatoriedade do sistema, checksum e PBKDF2.
- `bip-utils==2.12.2`: BIP-32/BIP-84, secp256k1, chaves e codificação/validação de
  endereços. Usa `coincurve` como backend secp256k1 padrão.

São bibliotecas conhecidas, com código público e testes. Isso não equivale a
afirmar que esta aplicação ou todas as suas dependências receberam auditoria
independente. Não implementamos ECC, PBKDF2 ou Bech32 manualmente.
[python-mnemonic](https://github.com/trezor/python-mnemonic),
[bip-utils](https://github.com/ebellocchia/bip_utils).

Os testes usam `unittest`, da biblioteca padrão. A instalação fica em `.venv/`,
sem modificar configurações globais. As dependências transitivas são resolvidas
pelo pip; `requirements.txt` não é um lock completo com hashes.

## 1. Gerar um alvo controlado

```bash
python main.py generate
python main.py generate --network regtest
```

Gera 128 bits aleatórios, produz 12 palavras válidas e deriva a primeira chave
externa da conta zero: `m/84'/1'/0'/0/0`. Exibe mnemonic, endereço, caminho e rede.
As chaves privada e pública são derivadas em memória, mas não impressas pela CLI.

A mnemonic aparece no terminal somente como resultado solicitado. Não existe
salvamento automático, arquivo de carteira ou log da aplicação. Guarde-a
temporariamente para o exercício e oculte uma palavra ao executar a busca.

Por padrão, a passphrase BIP-39 é vazia. Para usar uma passphrase conhecida:

```bash
python main.py generate --passphrase
python main.py brute-force --passphrase
```

A entrada ocorre sem eco; na geração, é preciso digitá-la duas vezes. Use a mesma
passphrase na busca. O laboratório não enumera passphrases. Se entrada sem eco
não estiver disponível, a operação é recusada em vez de expor a passphrase.

## 2. Recuperar palavras no espaço limitado

Modo interativo, recomendado para os dados do exercício:

```bash
python main.py brute-force
```

Informe o endereço gerado e as 12 palavras, substituindo uma a onze por `?`.
O modelo é solicitado sem eco. Não precisa informar índices separadamente.
Para regtest, use `--network regtest` tanto na geração quanto na busca.

Este exemplo reproduzível usa exclusivamente um vetor público de teste:

```bash
python main.py brute-force \
  --target-address tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl \
  --template "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?"
```

O resultado esperado é a palavra `about`, na quarta tentativa. O checksum
descarta as três primeiras combinações; somente uma derivação chega à comparação.
A frase completa desse exemplo é pública e **não deve receber dinheiro**.

Também é possível mascarar posições não adjacentes. As palavras conhecidas nunca
são alteradas; não há correção automática de palavras, procura de outros caminhos
ou tentativa de outras redes. O modelo deve conter exatamente 12 palavras,
com 1 a 11 `?`, e palavras conhecidas da lista English em minúsculas.

O limite de onze posições é fixo, sem opção de CLI para ampliá-lo:

| Posições desconhecidas | Combinações brutas | Válidas esperadas pelo checksum |
| --- | ---: | ---: |
| 1 | 2.048 | aproximadamente 128 |
| 2 | 4.194.304 | aproximadamente 262.144 |
| 3 | 8.589.934.592 | aproximadamente 536.870.912 |
| 4 | 17.592.186.044.416 | aproximadamente 1.099.511.627.776 |
| 5 | 36.028.797.018.963.968 | aproximadamente 2.251.799.813.685.248 |
| 6 | 73.786.976.294.838.206.464 | aproximadamente 4.611.686.018.427.387.904 |
| 7 | 151.115.727.451.828.646.838.272 | aproximadamente 9.444.732.965.739.290.427.392 |
| 8 | 309.485.009.821.345.068.724.781.056 | aproximadamente 19.342.813.113.834.066.795.298.816 |
| 9 | 633.825.300.114.114.700.748.351.602.688 | aproximadamente 39.614.081.257.132.168.796.771.975.168 |
| 10 | 1.298.074.214.633.706.907.132.624.082.305.024 | aproximadamente 81.129.638.414.606.681.695.789.005.144.064 |
| 11 | 2.658.455.991.569.831.745.807.614.120.560.689.152 | aproximadamente 166.153.499.473.114.484.112.975.882.535.043.072 |

Aceitar até 11 posições demonstra o espaço de busca matemático; não implica que
esses espaços sejam viáveis para execução completa. Mesmo duas posições podem
levar minutos, conforme a máquina e a posição da solução; espaços maiores são
impraticáveis para concluir com esta implementação serial.

Quando a última palavra é desconhecida, exatamente 1/16 das combinações é válida.
Se ela é conhecida e outras posições variam, essa proporção é uma expectativa;
os contadores exibem os valores realmente observados. Duas palavras já podem
levar minutos, dependendo da máquina e de onde está a solução.

Os candidatos são enumerados na ordem da wordlist, variando a posição mais à
direita primeiro. A geração usa um iterador, sem armazenar milhões de frases.

```text
12 palavras candidatas
  → checksum BIP-39 válido?
      não → contar descarte e continuar
      sim → PBKDF2-HMAC-SHA512 → seed de 64 bytes
          → BIP-32 → caminho BIP-84 → chave privada → chave pública
          → endereço P2WPKH → candidate_address == target_address
              igual → encerrar com sucesso e exibir a mnemonic
              diferente → continuar no mesmo espaço
```

O endereço deve ser P2WPKH válido da rede selecionada: witness v0, programa de
20 bytes, checksum Bech32 correto e formato canônico em minúsculas. Endereços
mainnet, P2WSH e Taproot são rejeitados. Endereços Bech32 totalmente maiúsculos
também são recusados pela interface para manter a comparação textual exata.

Ao encontrar, exibe mnemonic, endereço derivado, tentativas e tempo total. Ao
esgotar o espaço, informa ausência de correspondência. Uma passphrase, palavra
conhecida, rede ou caminho diferente pode explicar um alvo não encontrado.

### Estatísticas e interrupção

```bash
python main.py brute-force --update-interval 2
```

O intervalo padrão é 1 segundo, com mínimo de 0,1 segundo. Há uma atualização
inicial, atualizações periódicas e uma final; nenhuma saída por candidato.
Progresso e avisos vão para `stderr`; resultados vão para `stdout`.

- `Attempts`: candidatos totalmente concluídos; rejeitados no checksum ou comparados
  até o fim. Um candidato interrompido no meio não entra neste contador.
- `Valid mnemonics`: candidatos que passaram no checksum BIP-39 e entraram no PBKDF2.
- `Checksum rejected`: descartes antes de PBKDF2/BIP-32/BIP-84.
- `Rate`: combinações examinadas / tempo decorrido.
- `Checksum-valid`: candidatos que passaram no checksum / tempo decorrido.
- `Elapsed`, `Total`, `Progress`: tempo, espaço bruto e percentual examinado.
- `ETA`: tempo estimado para **esgotar o espaço restante**, pela média observada.

Em execução normal, `Attempts = Valid mnemonics + Checksum rejected` e os contadores
`seeds_derived`, `derivations`, `addresses_generated` e `comparisons` são iguais a
`Valid mnemonics`. `matches` só aumenta quando a comparação retorna igualdade.
Se houver interrupção/erro durante uma etapa válida, `in_flight=1` identifica a
tentativa parcial; `Attempts` continua contando apenas candidatos concluídos.
O percentual pode ser pequeno
quando um alvo é encontrado cedo; não é forçado a 100%. A ETA oscila, especialmente
no começo, e não prevê a posição da solução. `Ctrl+C` interrompe e mostra as
estatísticas das tentativas concluídas, sem salvar checkpoint ou candidatos.

### Auditoria de contabilidade

O enumerador cria exatamente um candidato por iteração. O checksum é validado antes
de `mnemonic_to_seed`; somente um candidato válido executa PBKDF2. Depois que a seed
retorna, `wallet_from_seed` realiza a derivação BIP-32/BIP-84 e produz o endereço;
somente então a comparação e o contador de `matches` são executados. Os contadores
de etapas são inteiros e são serializados como strings pela API para que o JavaScript
use `BigInt` sem perda de precisão.

| Métrica | Fonte real | Fórmula/evento | Exata ou estimada |
| --- | --- | --- | --- |
| Tentativas | enumerador | `+1` após descarte ou comparação concluída | exata |
| Checksum válidos | `is_valid_mnemonic` | `+1` quando retorna verdadeiro | exata |
| Checksum inválidos | `is_valid_mnemonic` | `+1` quando retorna falso | exata |
| Seeds derivadas | retorno de `mnemonic_to_seed` | `+1` após PBKDF2 retornar | exata |
| Derivações | retorno de `wallet_from_seed` | `+1` após BIP-32/BIP-84 retornar | exata |
| Endereços gerados | `Wallet.address` retornado | `+1` junto da carteira concluída | exata |
| Comparações | igualdade endereço/endereço-alvo | `+1` antes da comparação | exata |
| Correspondências | resultado da igualdade | `+1` quando é verdadeira | exata |
| Taxa | `perf_counter` | tentativas concluídas / tempo decorrido | medida |
| Espaço total | `SearchTemplate` | `2048^K` em inteiro | exata |
| Porcentagem | `SearchStats`/`BigInt` | tentativas / total, escala 1.000.000 | exata até 4 casas |
| ETA | taxa observada | combinações restantes / taxa | estimada |

Uma amostra é emitida somente para uma tentativa já concluída. Para checksum inválido,
`last_derived_address` é nulo e a próxima etapa é descarte imediato; para checksum
válido, ela contém o endereço produzido pela própria tentativa.

| Código de saída | Significado |
| --- | --- |
| 0 | Geração/benchmark concluído ou endereço-alvo exato encontrado |
| 1 | Espaço de busca esgotado sem correspondência |
| 2 | Entrada ou argumento inválido |
| 130 | Interrupção pelo usuário |

### Acompanhar o saldo do alvo durante a busca

O monitor se conecta exclusivamente ao Bitcoin Core em `127.0.0.1`, verifica que
o nó está em **regtest** e consulta os UTXOs do endereço-alvo configurado. As
mnemonics, seeds e chaves privadas nunca são enviadas ao nó. O saldo não influencia
o resultado da busca: somente a igualdade exata de endereço encerra com sucesso.

No ambiente desta implementação, um nó isolado já foi iniciado na porta `18443`,
com dados em `.lab-regtest/`. Para iniciá-lo novamente, ou em outra instalação
Linux que já tenha Bitcoin Core:

```bash
mkdir -p .lab-regtest
bitcoind -regtest=1 -datadir="$PWD/.lab-regtest" -conf=/dev/null \
  -nosettings -server=1 -disablewallet=1 -networkactive=0 \
  -listen=0 -dnsseed=0 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
  -rpcport=18443 -nodebuglogfile -daemonwait
```

O nó fica sem conexões P2P, sem carteira carregada e sem alterar configurações
globais. Ele cria seus dados de blockchain e um cookie de autenticação dentro
de `.lab-regtest/`, que está no `.gitignore`. O cookie é lido somente em memória
pelo cliente RPC e não é exibido nem passado como argumento de linha de comando.

```bash
python main.py generate --network regtest
python main.py brute-force --network regtest --watch-target-balance
```

Informe o endereço gerado e o modelo com uma a onze posições desconhecidas.
Para um exemplo com dados públicos de teste:

```bash
python main.py brute-force --network regtest --watch-target-balance \
  --target-address bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk \
  --template "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?"
```

A saída acrescenta, por exemplo:

```text
Saldo do ALVO: 0.00000000 BTC de teste (regtest) | 0 sat | Bloco: 0 | ...
```

A blockchain recém-criada está vazia, portanto saldo zero é esperado. Um saldo
positivo só aparece se existirem UTXOs desse endereço na cadeia regtest local.
O programa não minera, cria transações ou financia endereços automaticamente.

A primeira leitura acontece antes da cronometragem da busca. Depois, uma thread
verifica o nó a cada cinco segundos, sem bloquear o loop de candidatos. Enquanto
o bloco de referência não mudar, reutiliza o saldo já consultado. Em buscas que
terminam rapidamente, pode haver apenas a leitura inicial. Ao terminar ou
interromper, o monitor deixa de agendar consultas; uma requisição já em andamento
pode concluir dentro do seu timeout.

As consultas são somente `getblockchaininfo` e
`scantxoutset start ["addr(ENDEREÇO-ALVO)"]`. Não há descritores com intervalos,
consulta de endereços candidatos, descoberta de carteiras ou conexão com explorer.
A consulta UTXO pode percorrer os dados locais do nó, razão pela qual este monitor
fica limitado a regtest e reutiliza os resultados por bloco.
[RPC scantxoutset](https://bitcoincore.org/en/doc/30.0.0/rpc/blockchain/scantxoutset/).

O valor é a soma dos UTXOs **confirmados daquele endereço**, não o saldo agregado
de uma carteira com vários endereços. Não inclui alterações pendentes no mempool
e pode incluir coinbase ainda imatura; não representa necessariamente valor
imediatamente disponível para gastar. Todos os valores são BTC de teste, sem
valor econômico real. Os cálculos usam `Decimal` e satoshis inteiros.

Se o nó não responder, o cookie não existir ou a resposta não puder ser validada,
o painel exibe **saldo indisponível**, nunca um zero presumido. A busca local
continua e o monitor tenta novamente no próximo intervalo. Nós mainnet/testnet
são recusados antes da consulta de UTXOs, mesmo se estiverem na porta configurada.

Para outro nó **regtest local**, configure somente porta e arquivo de cookie:

```bash
python main.py brute-force --network regtest --watch-target-balance \
  --rpc-port 18444 --rpc-cookie-file /caminho/local/regtest/.cookie
```

Para encerrar o nó isolado deste laboratório:

```bash
bitcoin-cli -regtest -datadir="$PWD/.lab-regtest" -conf=/dev/null -rpcport=18443 stop
```

### Painel ao vivo

Para acompanhar as tentativas em uma interface local, inicie o painel em outro
terminal:

```bash
python main.py web --start-regtest
```

Abra [http://127.0.0.1:8765](http://127.0.0.1:8765). O servidor escuta somente
na interface de loopback; não é um serviço web público. `--start-regtest` inicia
o nó isolado do laboratório se ele ainda não estiver disponível. Se o nó já foi
iniciado manualmente, use apenas `python main.py web`.

O painel possui dois ritmos. `Visual` pausa cada tentativa real por 20 ms, para
que a palavra em teste e as etapas checksum → seed → derivação → comparação
possam ser vistas. `Sem pausa` mantém a velocidade máxima. Nos dois casos a
busca continua limitada a uma a onze posições desconhecidas; a amostra exibida
é uma janela de observação, e os contadores são os números completos.

O seletor `Operação` também oferece `Validar uma mnemonic completa`. Nesse modo,
cole exatamente as 12 palavras, sem `?`: o laboratório faz uma única validação
de checksum, derivação BIP-39/BIP-84 e comparação com o alvo. Isso permite testar
uma frase completa que você controla, mas não enumera nem tenta recuperar uma
mnemonic desconhecida de 12 palavras (`2048^12`).

Ele atualiza continuamente tentativas, válidas, descartes, taxa, ETA, endereço
derivado e saldo do alvo. O saldo é lido via RPC local regtest a cada cinco
segundos. Um saldo positivo isolado não dispara sucesso: o alerta verde aparece
somente quando a mnemonic candidata produziu exatamente o endereço-alvo e uma
verificação posterior confirmou UTXOs positivos desse mesmo endereço. O alerta
sonoro é opcional e depende do navegador permitir áudio.

Depois da correspondência exata, o botão `Revelar chave de laboratório` abre uma
janela local contendo a chave privada hexadecimal, a mnemonic, a chave pública e
o endereço conferido. A chave não aparece no estado de acompanhamento, não é
salva em arquivo e é apagada da janela ao ocultá-la ou limpar o experimento.
Revelar uma chave de regtest não assina nem transmite transações.

O painel rejeita testnet/mainnet, bloqueia mais de onze `?` na busca limitada,
aceita uma busca por vez e invalida o botão de revelação quando o experimento é
limpo. Não há endpoint para varrer endereços, consultar saldo de candidatos ou
exportar chaves.

Para validar a interface em navegadores instalados localmente, as dependências
opcionais e o script de QA ficam separados das dependências de runtime:

```bash
python -m pip install -r requirements-dev.txt
python scripts/browser_qa.py
```

Esse QA usa somente o alvo público regtest do README, captura estados de busca,
resultado sem saldo e alerta positivo simulado, e não cria transações. Ele cobre
Chromium em 1920, 1366, 1024, 768, 390, 360 e 320 px e Firefox em 1366 e 390 px.

## 3. Benchmark e projeções

```bash
python main.py benchmark
python main.py benchmark --samples 10000
```

O padrão é 1.000 derivações medidas; o limite é 10.000. Uma derivação adicional
aquece as bibliotecas antes da medição. As mnemonics do benchmark vêm de fixtures
determinísticas públicas baseadas em SHA-256, sem qualquer endereço-alvo, procura
de carteira ou impressão de chaves. A preparação das fixtures fica fora do tempo
medido. Cada amostra medida valida checksum, gera seed, deriva chaves e endereço.

O resultado informa derivações válidas/s, tempo médio e dois grupos temporais.
O primeiro, exibido como `mnemonic_to_seed (validação + PBKDF2)`, mede a chamada
inteira da API: normalização, a validação/checksum feita por
`mnemonic_to_seed()` (que chama `is_valid_mnemonic()` e normaliza novamente) e,
só então, `Mnemonic.to_seed()` com sua própria normalização e PBKDF2-HMAC-SHA512.
Portanto, esse número **não é PBKDF2 puro**. O segundo mede
`wallet_from_seed()`, agrupando BIP-32/BIP-84, operações de chave secp256k1 e
produção/codificação do endereço conforme executadas por `bip-utils`.

O tempo total inclui o loop, as medições e eventuais atualizações periódicas; a
preparação das fixtures e o aquecimento ficam fora dele. O benchmark usa
passphrase vazia. A segunda validação de checksum permanece deliberadamente: na
busca, um candidato válido já passou por `is_valid_mnemonic()`, mas a API de seed
continua segura quando chamada isoladamente com uma entrada inválida. Não se deve
remover essa validação sem uma mudança de contrato e uma análise própria.

As projeções usam a taxa de **mnemonics válidas derivadas**, não a taxa bruta que
inclui descartes rápidos. Para cada fração de 1%, 50% e 100%:

```text
segundos = fração × 2^bits_de_entropia / derivações_válidas_por_segundo
anos = segundos / (365,25 × 24 × 60 × 60)
```

24 palavras são apenas uma projeção matemática usando a taxa medida com 12;
não há geração ou busca de frases de 24 palavras. Hardware, implementação e
paralelização mudam a taxa. Mantida a hipótese de entropia uniforme e secreta,
esses fatores não tornam a enumeração completa uma estratégia praticável.

Percorrer 50% não garante achar a mnemonic: supondo uma única solução e posição
uniforme na enumeração, corresponde a aproximadamente 50% de chance e ao custo
médio de busca. A execução real também depende de todas as palavras conhecidas,
da passphrase e do caminho estarem corretos.

### Baseline serial e profiling de referência

Em 15/09/2026, neste estado de trabalho, `python main.py benchmark --samples
1000` foi executado em AMD Ryzen 5 5500 (6 núcleos / 12 CPUs lógicas), Linux
x86_64, Python 3.11.15, `mnemonic` 0.21, `bip-utils` 2.12.2 e `coincurve`
21.0.0, com um processo serial em testnet. É uma linha de base desta máquina,
não uma garantia para outras máquinas.

| Métrica | Resultado |
| --- | ---: |
| Derivações válidas medidas | 1.000 |
| Tempo total | 1,402073 s |
| Mnemonics válidas derivadas/s | 713,23 |
| Tempo médio por candidato válido | 1,402073 ms |
| `mnemonic_to_seed` (validação + PBKDF2) | 0,853786 s |
| `wallet_from_seed` (BIP-32/BIP-84 + chaves/endereço) | 0,547673 s |

| Palavras | Fração | Segundos | Anos |
| --- | ---: | ---: | ---: |
| 12 | 1% | 4,771006 × 10^33 | 1,511841 × 10^26 |
| 12 | 50% | 2,385503 × 10^35 | 7,559203 × 10^27 |
| 12 | 100% | 4,771006 × 10^35 | 1,511841 × 10^28 |
| 24 | 1% | 1,623489 × 10^72 | 5,144527 × 10^64 |
| 24 | 50% | 8,117447 × 10^73 | 2,572264 × 10^66 |
| 24 | 100% | 1,623489 × 10^74 | 5,144527 × 10^66 |

Estes valores são uma medição, não uma promessa de desempenho. Nesta execução,
o grupo inclusivo `mnemonic_to_seed` correspondeu a aproximadamente 61% do tempo
total e `wallet_from_seed` a aproximadamente 39%; isso não atribui 61% ao
PBKDF2 isoladamente. O profiling detalhado abaixo é necessário antes de qualquer
otimização.

Para obter uma decomposição reproduzível e limitada, separada da execução normal:

```bash
python scripts/profile_reference.py --samples 64
```

O script usa somente fixtures BIP-39 públicas e determinísticas, aceita de 1 a
256 amostras e não enumera um modelo, não usa RPC e não recebe mnemonics do
usuário. Ele mede separadamente a preparação das fixtures (fora do baseline),
montagem do candidato, primeira validação, a chamada inteira de `mnemonic_to_seed`,
`wallet_from_seed`, comparação e o residual de loop/timers. Também executa uma
sonda PBKDF2 direta sobre frases English canônicas: ela exclui validação e
normalização e, por isso, é diagnóstica e nunca deve ser somada ao tempo do
pipeline.

O `cProfile` do script informa por função tanto tempo exclusivo (corpo da função)
quanto inclusivo (corpo mais chamadas filhas). Funções aninhadas, como
`mnemonic_to_seed` → `is_valid_mnemonic` → `Mnemonic.to_seed`, não são categorias
aditivas: somar tempos inclusivos delas produziria dupla contagem. A API atual da
`bip-utils` não permite separar com precisão, sem reimplementar ou instrumentar a
biblioteca, BIP-32/BIP-84, multiplicação secp256k1 e codificação de endereço;
eles permanecem agrupados em `wallet_from_seed`.

O pipeline serial atual é a referência de correção a preservar:

```text
mnemonic → seed → chave → endereço → comparação
```

Qualquer implementação acelerada futura deverá provar paridade com ele em
fixtures públicas e candidatos sintéticos. Os testes atuais já cobrem vetores
BIP-39/BIP-32/BIP-84 e as primitivas `is_valid_mnemonic`, `mnemonic_to_seed` e
`wallet_from_seed`; quando houver um backend real, a adição apropriada é uma
interface de resultado explícita e testes `reference_result(candidate) ==
accelerated_result(candidate)`, sem substituir ou remover esta referência.

## Entendendo os padrões

### BIP-39, mnemonic e seed

BIP-39 representa entropia como palavras. A lista tem 2.048 entradas porque cada
índice ocupa 11 bits: `2^11 = 2048`. Uma mnemonic de 12 palavras codifica 128 bits
aleatórios mais 4 bits de checksum, obtidos do SHA-256 da entropia.

Assim, `2048^12 = 2^132` conta todas as sequências; apenas `2^128` têm checksum
válido. O checksum detecta alguns erros, mas não acrescenta entropia. Para 24
palavras, são 256 bits de entropia e 8 de checksum: `2^256` frases válidas entre
`2048^24 = 2^264` sequências.

A mnemonic é a frase; a seed é um resultado binário de 64 bytes. A conversão usa
PBKDF2-HMAC-SHA512 com 2.048 iterações, a frase como senha e `"mnemonic" + passphrase`
como salt, com normalização Unicode NFKD. A passphrase padrão é vazia. Uma seed
de 512 bits de comprimento não transforma 128 bits aleatórios em 512 bits de
entropia. Palavras escolhidas por uma pessoa não oferecem automaticamente 128
bits. [Especificação BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).

### BIP-32 e BIP-84

BIP-32 cria uma árvore determinística de chaves a partir da seed. O mestre deriva
por HMAC-SHA512 com a chave `Bitcoin seed`; os nós carregam material de chave e
chain code. As derivações filhas usam índices normais ou hardened. A chave privada
é um escalar secp256k1; a pública é o ponto correspondente na curva, calculado pela
biblioteca. [Especificação BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

BIP-84 define a organização dessa árvore para endereços SegWit nativos P2WPKH.
O endereço codifica um programa witness v0 com HASH160 da chave pública comprimida,
usando Bech32. [Especificação BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki).

No caminho fixo `m/84'/1'/0'/0/0`:

| Componente | Significado |
| --- | --- |
| `m` | Raiz privada BIP-32 |
| `84'` | Propósito BIP-84, hardened |
| `1'` | Coin type de redes de teste, hardened |
| `0'` | Conta zero, hardened |
| `0` | Cadeia externa, para recebimento |
| `0` | Primeiro endereço |

O apóstrofo marca hardened. Usamos coin type `1` também em regtest.
[Registro SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md).

### Testnet, regtest e mainnet

Mainnet é a rede Bitcoin com valor econômico real. Testnet é uma rede pública de
testes. Regtest permite uma rede de testes controlada localmente, com produção de
blocos sob controle do operador. Para P2WPKH, os prefixos são `bc1q`, `tb1q` e
`bcrt1q`, respectivamente.
[Parâmetros do Bitcoin Core](https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp).

Aqui, selecionar uma rede muda os parâmetros de derivação/codificação. Apenas
`--watch-target-balance` abre uma conexão RPC com o nó regtest local.
Testnet e regtest compartilham as chaves para a mesma
mnemonic, passphrase e caminho, mas usam codificações de endereço distintas.
Testnet3 e testnet4 compartilham o formato `tb`; o endereço sozinho não distingue
essas redes. Os demais exercícios continuam sem necessidade de nó.

### Por que a busca completa é impraticável?

`2^128 ≈ 3,4028237 × 10^38` possibilidades uniformes formam um espaço muito maior
que o experimento de uma a onze palavras. Conhecer dez ou onze palavras já remove
quase toda a incerteza que torna uma mnemonic completa resistente. O laboratório
mede o custo dessa parte pequena e calcula o custo da enumeração completa.

As projeções de 24 palavras descrevem **enumerar mnemonics**, não a resistência
de um endereço individual a toda forma de ataque. P2WPKH contém um hash de 160
bits; frases diferentes podem produzir o mesmo endereço. Uma correspondência
confirma somente a condição pedida (`candidate_address == target_address`), não
uma prova matemática de que a frase é a original. A probabilidade disso afetar
este espaço limitado é desprezível sob as hipóteses criptográficas usuais.

## Testes

```bash
python -m unittest discover -v
python -m pip check
```

Na validação realizada em 15/09/2026 neste estado, `python -m unittest discover
-v` executou **106 testes**, todos aprovados, com **2 integrações RPC opcionais
ignoradas** sem `BIP39_LAB_LIVE_REGTEST=1`. A contagem inclui os testes do
profiling limitado; os dois testes live continuam opt-in e exigem Bitcoin Core
regtest local. O tempo varia conforme a máquina.

Para executar os testes reais de RPC com o nó regtest local iniciado:

```bash
BIP39_LAB_LIVE_REGTEST=1 python -m unittest tests.test_regtest_integration -v
```

Cobertura dos comportamentos principais:

- Quatro vetores BIP-39 de 12 palavras: entropia, mnemonic, checksum e seed com
  `TREZOR`; também seed com passphrase vazia e normalização Unicode.
- Mestre BIP-32 publicado, caminho explícito, chaves, determinismo e endereços
  conhecidos de testnet/regtest.
- Recuperação de uma palavra de uma mnemonic recém-gerada; duas palavras com
  avanço da primeira posição desconhecida; limite de onze palavras validado sem
  executar uma enumeração completa; posições não adjacentes e passphrase.
- Espaço de 2.048 combinações esgotado sem falso positivo: exatamente 128
  derivações válidas e 1.920 rejeições quando a última palavra está mascarada.
- Descarte antes de derivar, parada no alvo, preservação das palavras conhecidas,
  validação de entradas, estatísticas, ETA, progresso e interrupção.
- Limites do benchmark e unidades das seis projeções.
- CLI e execução dos três comandos com chamadas de conexão/DNS bloqueadas por
  mocks, confirmando que os fluxos padrão não tentam acessar a rede.
- Monitor com valores zero/positivos, erros de RPC, valores decimais exatos,
  verificação de rede, alvo fixo, reaproveitamento por bloco, resposta indisponível
  e consulta lenta em paralelo à busca. Valores positivos são fixtures simuladas
  dos testes; a consulta real ao nó recém-criado retornou zero satoshis no bloco 0.
- Sessão do painel, token de loopback, origem/host, CSP, rotas estáticas, limites
  de JSON e revelação autenticada da chave somente depois da correspondência exata.

Os testes com duas palavras encontram alvos deliberadamente próximos do início;
os testes de onze palavras verificam o limite e o tamanho do espaço sem executar
as 2.658.455.991.569.831.745.807.614.120.560.689.152 combinações na suíte. Não substituem uma auditoria
criptográfica independente. Dados e fontes dos vetores ficam em
[`tests/vectors.py`](tests/vectors.py); todos são públicos.

Também foi validado o ciclo real da CLI em subprocessos: gerar uma mnemonic
aleatória e recuperar uma palavra, em testnet e regtest, mantendo os dados
gerados apenas em memória durante a verificação. `pip check` não encontrou
dependências incompatíveis.

### CI

`.github/workflows/ci.yml` valida a referência em `push` e `pull_request` com
Python 3.11 e 3.12: instala apenas `requirements.txt`, executa `pip check`,
`unittest discover`, `compileall` e `node --check` no JavaScript principal. Não
instala Bitcoin Core, Playwright, GPU/CUDA nem usa segredos, APIs ou serviços
externos; por isso as integrações RPC live continuam ignoradas. As dependências
diretas instaladas localmente declaram suporte a Python 3.12 (`mnemonic >=3.8.1`,
`bip-utils >=3.7`), mas 3.12 não estava instalado nesta máquina para uma execução
local; a matriz de GitHub Actions ainda não foi executada no GitHub.

## Security boundaries

O software deliberadamente não busca carteiras com saldo e não tenta recuperar
fundos reais. Seu único critério de sucesso é a igualdade com o endereço-alvo
configurado pelo usuário. A busca enumerativa continua restrita ao modelo de uma
a onze palavras desconhecidas; a operação de 12 palavras completas valida apenas
a frase que o usuário forneceu.

- A aplicação aceita somente testnet/regtest. Mainnet não é uma opção de busca
  nem de geração, mesmo que a biblioteca tenha suporte a ela.
- Não existe varredura de endereços aleatórios, explorer ou descoberta de carteiras.
  O monitor opcional consulta somente UTXOs do alvo configurado, via RPC local em
  regtest. Nunca consulta o saldo dos endereços produzidos por cada tentativa.
- Não há criação, assinatura ou transmissão de transações, sweep, movimentação
  de fundos ou exportação automática de chaves encontradas.
- A busca não muda o alvo, não testa outros caminhos, não expande o número de
  posições desconhecidas e não procura uma segunda carteira após o sucesso.
- A posse do endereço é declarada pelo usuário. A aplicação não tem
  mecanismo de provar sua titularidade; use somente alvos controlados por você.
- Mnemonics/seeds/chaves ficam em memória. Os `repr` dos resultados escondem a
  mnemonic e as chaves. Não existe banco de mnemonics, telemetria ou log permanente
  de candidatos. O nó regtest mantém sua própria blockchain e cookie RPC no
  diretório ignorado `.lab-regtest/`; não recebe as mnemonics ou chaves do laboratório.

O terminal, o histórico do shell, gravações de sessão e redirecionamentos feitos
pelo usuário podem persistir o que for digitado ou exibido. Prefira os prompts
interativos e não redirecione a geração para arquivos versionados. `.gitignore`
cobre o ambiente virtual e nomes comuns de arquivos sensíveis, mas não detecta
segredos inseridos manualmente em arquivos arbitrários. Python não garante apagar
imediatamente objetos sensíveis da memória. Este laboratório não é uma carteira
para uso financeiro.

## Estrutura e limites atuais

```text
main.py
.github/workflows/ci.yml
bip39_lab/
  __init__.py
  wallet.py       # mnemonic, seed, BIP-32/BIP-84, chaves e endereço
  bruteforce.py   # enumeração limitada, comparação e estatísticas
  benchmark.py    # medição e projeções matemáticas
  balance.py      # monitor opcional do alvo, RPC local exclusivamente regtest
  dashboard.py    # sessão em memória do painel regtest
  web.py          # servidor HTTP restrito ao loopback
  static/         # HTML, CSS, JavaScript e favicon locais
  cli.py          # comandos e apresentação
tests/
  vectors.py
  test_wallet.py
  test_bruteforce.py
  test_benchmark.py
  test_cli.py
  test_balance.py
  test_dashboard.py
  test_web.py
  test_profile_reference.py
  test_regtest_integration.py
scripts/
  browser_qa.py           # QA opcional com Playwright/navegadores locais
  profile_reference.py    # baseline/profiling serial com fixtures públicas
requirements.txt
requirements-dev.txt
.gitignore
README.md
```

Somente English e 12 palavras; uma a onze posições desconhecidas; rede e caminho
fixados por execução; busca serial em um processo CPU. Há threads apenas para o
painel e a consulta opcional do saldo do alvo local; elas não paralelizam a busca.
Não há retomada/checkpoint: uma futura arquitetura de scheduler/batches precisa
ser definida antes de persistir estado sobre este enumerador serial. Não há GPU,
CUDA, OpenCL, cluster ou sistema distribuído. O monitor só aceita regtest e mostra
UTXOs confirmados, sem mempool. A passphrase precisa ser conhecida. O modo
benchmark não mede a velocidade de enumeração/descarte de modelos incompletos.

### Portabilidade conhecida

O núcleo Python não contém uma dependência explícita de Linux para a derivação
offline. Os comandos de instalação do README usam `source .venv/bin/activate`,
e o atalho de Bitcoin Core usa `/dev/null`, `$PWD`, `bitcoind` e `bitcoin-cli`;
essas instruções exigem adaptação em Windows. O início automático do nó em
`web.py` também passa `-conf=/dev/null` ao processo. A portabilidade para Windows,
incluindo caminhos, ativação de venv e gestão do Bitcoin Core, não foi implementada
nesta etapa.

Experimentos seguintes possíveis dentro dos mesmos limites: repetir o baseline
para observar variação, expandir o profiling somente quando uma separação for
tecnicamente confiável, comparar posições desconhecidas e conferir mais vetores
públicos. Qualquer mudança de arquitetura deve ser justificada por medições e por
paridade com a referência antes de ser implementada.
