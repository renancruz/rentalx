>>RF  => *Requisitos funcionais*
>>RNF => *Requisitos não funcionais*
>>RN  => *Regra de negócio*

# Cadastro de carro

  **RF**
    [] Deve ser possível cadastrar um novo carro.
    [] Deve ser possível listar todas as categorias


  **RN**
    [] Não deve ser possível cadastrar um carro com uma placa já existente.
    [] Não deve ser possível alter a placa de um carro já cadastrado.
    [] O carro deve ser cadastrado por padrão com disponibilidade.
    [] O usuário responsável pelo cadastro deve ser um usuário administrador.

# Listagem de carros

  **RF**
    [] Deve ser possível listar todos os carros disponíveis.
    [] Deve ser possível listar todos os carros disponíveis pelo nome da categoria
    [] Deve ser possível listar todos os carros disponíveis pelo nome da marca
    [] Deve ser possível listar todos os carros disponíveis pelo nome do carro


  **RN**
    [] O usuário não precisa estar logado no sistema.

# Cadastro de Especifiação no carro

  **RF**
    [] Deve ser possível cadastar uma especificação para um carro.
    [] Deve ser possível listar todas as especificações
    [] Deve ser possível listar todos os carros
    [] O usuário responsável pelo cadastro deve ser um usuário administrador.
  

  **RN**
    [] Não deve ser possível cadastrar uma especificação para um carro não cadastrado.
    [] Não deve ser possível cadastrar uma especificação já existente para o mesmo carro.

# Cadastro de imagens do carro

  **RF**
    [] Deve ser possível cadastrar a imagem do carro.
    [] Deve ser possível listar todos os carros.


  **RNF**
    [] Utilizar o multer para upload dos arquivos.


  **RN**
    [] O usuário deve poder cadastrar mais uma imagem para o mesmo carro.
    [] O usuário responsável pelo cadastro deve ser um usuário administrador.

# Aluguel de carro

  **RF**
    [] Deve ser possível cadastrar um aluguel


  **RN**
    [] O aluguel deve ter duração mínima de 24 horas.
    [] Não deve ser possível cadastrar um novo aluguel caso já exista um aberto para o mesmo usuário
    [] Não deve ser possível cadastrar um novo aluguel caso já exista um aberto para o mesmo carro.

