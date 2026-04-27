
FROM anchore/syft:latest
# O comando 'version' apenas mantém o container ativo se usado com um loop ou sleep,
# mas a melhor forma para estas imagens é usar o próprio binário em modo de espera.
ENTRYPOINT ["/syft"]
CMD ["version"]