import rsa
import base64


def AbrirArquivo(arq):
    arquivo = open(arq,'rb')
    conteudo = arquivo.read()
    arquivo.close()
    return conteudo

def VersãoDoSha(versao):
    versoes = {'1': 'MD5', '2': 'SHA-1', '3': 'SHA-224', '4': 'SHA-256', '5': 'SHA-384', '6': 'SHA-512'}
    escolha = versoes.get(versao)
    return escolha

def TamChave(op):
    chaves = {'1': 1024, '2': 2048, '3': 3072, '4': 4096}
    escolha = chaves.get(op)
    return escolha

def GeraChaves(tam):
    (chave_publica, chave_privada) = rsa.newkeys(tam)
    with open('chave_publica.txt', 'wb') as f:
      f.write(chave_publica.save_pkcs1('PEM'))
    with open('chave_privada.txt', 'wb') as f:
      f.write(chave_privada.save_pkcs1('PEM'))
    print('\nAs chaves foram geradas com sucesso!')
    print('Foram criados dois arquivos de chaves!\n')


def AssinaMensagem(mensagem, chave_privada, versao_sha):
    valor_hash = rsa.compute_hash(mensagem, versao_sha)
    print('Hash gerado: {}\n'.format(valor_hash))
    assinatura = rsa.sign_hash(valor_hash, chave_privada, versao_sha)
    assinatura = base64.b64encode(assinatura)
    print('Texto da assinatura gerado: {}\n'.format(assinatura))
    with open('texto_assinatura.txt', 'wb') as f:
        f.write(assinatura)
    print('A mensagem foi assinada com sucesso!')
    print('Foi criado um arquivo de texto da assinatura!\n')

def VerificaAssinatura(mensagem, chave_publica, texto_assinatura):
    try:
        #nessa função o método hash é identificado automaticamente pela assinatura, entao não precisou colocar o método hash.
        texto_assinatura = base64.b64decode(texto_assinatura)
        rsa.verify(mensagem, texto_assinatura, chave_publica)
        print('Resultado da verificação: Verdadeiro\n')
    except:
        print('Resultado da verificação: Falso\n')

def Main():
    op = -1
    while(op!=0):
        print('-----MENU-----')
        print('1.Gerar chaves\n2.Assinar mensagem\n3.Verificar assinatura\n0.Sair\n')
        op = int(input('Digite uma opção:\n'))
        if op == 1:
            escolha_chave = input('Digite o tamanho das chaves:\n1.1024\n2.2048\n3.3072\n4.4096\n')
            tam = TamChave(escolha_chave)
            GeraChaves(tam)
        elif op == 2:
            chave_privada = rsa.PrivateKey.load_pkcs1(AbrirArquivo('chave_privada.txt'))
            mensagem = AbrirArquivo('mensagem.txt')
            versao_sha = input('Escolha a versão do SHA:\n1.MD5\n2.SHA-1\n3.SHA-224\n4.SHA-256\n5.SHA-384\n6.SHA-512\n')
            versao_sha = VersãoDoSha(versao_sha)
            print('Versão do SHA: {}'.format(versao_sha))
            AssinaMensagem(mensagem, chave_privada, versao_sha)
        elif op == 3:
            chave_publica = rsa.PublicKey.load_pkcs1(AbrirArquivo('chave_publica.txt'))
            mensagem = AbrirArquivo('mensagem.txt')
            texto_assinatura = AbrirArquivo('texto_assinatura.txt')
            VerificaAssinatura(mensagem, chave_publica, texto_assinatura)
        elif op == 0:
            print('\nFim do programa')
Main()
            
            
