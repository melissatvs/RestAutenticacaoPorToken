> Esse Fork é do projeto usado como referência no [artigo](https://www.linkedin.com/pulse/autentica%C3%A7%C3%A3o-baseada-em-token-uma-aplica%C3%A7%C3%A3o-rest-tarcisio-carvalho/) do LinkedIn, escrito por [Tarcisio Carvalho](https://www.linkedin.com/in/tarcisio-carvalho-69333830/). 
> Trouxe o artigo adaptado aqui, que é uma explicação bem detalhada do projeto.
> Usei como uma das bases de estudo sobre uso de Tokens e Segurança em uma API Rest durante o [AceleraDev](https://www.codenation.dev/) de Python da [Stone](https://www.stone.com.br/)

# Autenticação baseada em token em uma aplicação REST

## Introdução

A segurança é uns dos pontos mais vitais de uma aplicação, e devemos sempre dedicar tempo e recursos para fazer a segurança na melhor forma possível.

Em uma aplicação REST a formas tradicionais de fazer a autenticação e segurança podem não ser melhor caminho, por isso nesse tutorial vamos demonstrar como fazer a parte autenticação mais comum pra aplicações  REST que á autenticação baseada em token e para o melhor entendimento, será construído uma aplicação java do inicio e detalhando cada passo para fazer a autenticação.

Tutorial será focado somente na autenticação e por isso já assumirei que o leitor já tem conhecimento prévio de como funciona uma aplicação REST utilizando jersey e Também conhecimento com protocolo HTTP.

Se o leitor não conhece a padrão de projeto REST segue alguns links que pode ter ajudar a entender esse assunto :

[https://www.w3.org/2001/sw/wiki/RESTb](https://www.w3.org/2001/sw/wiki/RESTb) (Inglês)

[http://www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm](http://www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm) (Inglês)

[https://becode.com.br/o-que-e-api-rest-e-restful/](https://becode.com.br/o-que-e-api-rest-e-restful/) (Português)

## Vantagens autenticação baseada em token?

Como pode ver nesse excelente artigo [The Ins and Outs of Token Based Authentication](https://scotch.io/tutorials/the-ins-and-outs-of-token-based-authentication) é mostrado as vantagens de utilizar o token como forma de autenticação, podemos resumir nas seguintes vantagens:

### Estabilidade

Como o token é salvo é no lado do cliente, e podemos colocar as informações do cliente no próprio token, a assim poupando o servidor de armazenar isso.

### Segurança

A cada requisição é enviado o token e não um cookie, e mesmo que sua implementação do lado do cliente utilize um cookie ele so vai servir pra armazenar o token, e não uma session que poderia ser manipulada e previnir ataques CSRF.

## Como funciona a autenticação baseada em token

Em uma autenticação baseada em token, o cliente troca suas credenciais(exemplo: login e senha) por um token, depois disso em vez de enviar as credenciais a cada requisição o cliente so envia o token pra a autenticação e autorização.

Resumindo esses são os passos de uma autenticação com token tem:

1. O cliente envia as credenciais para o servidor.
2. O servidor autentica as credenciais e gera um token.
3. O servidor envia o token para o cliente.
4. O cliente salva esse token e envia ele em um header em cada requisição
6. O servidor, em cada requisição extrai o token e verifica se o token e valido ou não
	- Se o token é valido, o servidor aceita a requisição
	- Se o token é inválido, o servidor rejeita a requisição
7. O servidor pode ter um endpoint que renova o token

## A aplicação

A aplicação vai ser um simples conversor de distâncias em milhas para quilometro e vise e versa.

A aplicação tem somente 3 endpoints:

1.  Um end point que é responsável de fazer a autenticação do usuário
2.  Um end point que vai converter milhas para quilômetros
3.  Um end point que vai converter quilômetros para milhas

E vamos fazer que seja preciso estar autenticado no sistema e ter o nível de acesso adequado para ter acesso a qualquer um do endpoint.

## O que vai ser utilizado para construção da aplicação

Para parte REST vamos usar a implantação do JAX-RS o jersey na versão 2.0. 

O jersey é uma das varias implementações que a especificação JAX-RS possui e por sua vez o JAX-RS é a especificação Java para o uso de Web Services Rest, você pode saber mais nesse link: [http://blog.kolaborativa.com/2013/08/jax-rs/](http://blog.kolaborativa.com/2013/08/jax-rs/) .

Para obter o jersey e saber como instalar no seu projeto acesse esse link: [https://github.com/jersey](https://github.com/jersey)

Vamos usar a biblioteca GSON do google pra fazer a parte de conversar de JSON pra objeto java e vise e versa.

Para obter o GSON e saber como instalar no seu projeto acesse esse link: [https://github.com/google/gson](https://github.com/google/gson)

Para testar as chamadas dos endpoint da nossa aplicação, utilizaremos o Postman. 

Ele pode ser obtido no seguinte link: [https://www.getpostman.com/](https://www.getpostman.com/)

O token que vamos utilizar vai ser o JWT(JSON Web Token), para facilitar o desenvolvimento vamos usar uma biblioteca chamada JJWT que auxiliar na geração e validação do token.

A biblioteca JJWT poder ser obtida no seguinte link : [https://github.com/jwtk/jjwt](https://github.com/jwtk/jjwt)

## O que o JWT?

O JWT(JSON Web Token) é definido no site oficial na seguinte forma [http://jwt.io](http://jwt.io): “JWT é um padrão aberto que define uma forma compacta e auto-contida para transmitir de forma segura, informações entre duas partes como objeto JSON”.

O JWT é divido em três partes separadas por um “.” essas três partes são o Header, Payload e a Signature

### Header

O header é a primeira parte do JWT e ele é divido em duas partes, o algoritmo de codificação e o tipo do token e essas duas partes são encodadas em Base64, ficaria assim:

	{
	  “alg” : "HS256",
	  “typ” : "JWT"
	}


A propriedade “alg" define o algoritmo do token que nesse caso é o HMAC SHA256 e a propriedade “typ" é o tipo do token que é o JWT. 

Após ser enconcado em Base64 o header fica assim:

	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9


### Payload

O payload é a informação que vai ser enviada, por exemplo podemos enviar o nome do usuário e uma propriedade que diz se ele é administrador ou não, ficaria assim :

	{
	  “nome" : "fulano”,
	  “admin” : true
	}


Após ser enconcado em Base64 o payload ficaria assim:

	eyJub21lIjoiRnVsYW5vIiwiYWRtaW4iOnRydWV9


### Signature

Por último temos signature que é o header e payload codificado com o algoritmo do header junto com uma palavra segredo que é usada pra codificar e não deve ser compartilhada com ninguém.

Após ser enconcado em Base64 ficaria assim:

	IShPdPgMqjygLcv6FpePbFuRLJHBTdeKSNDQIpR-X2E


Então nosso token completo fica assim:

	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
	.
	eyJub21lIjoiRnVsYW5vIiwiYWRtaW4iOnRydWV9
	.
	IShPdPgMqjygLcv6FpePbFuRLJHBTdeKSNDQIpR-X2E 


## Construindo a aplicação

Com o projeto criado e com as dependências do jersey, JJWT e do Gson incluídas no projeto devemos começar criando o pacote e classe que contém os endpoint de conversão das medidas

Primeiro criamos o package br.com.projetoRest.service e dentro desse package criamos a classe ConversorMedidasService.java.

Com a classe criada devemos por em cima da definição da classe a annotation @Path que configura a url do endpoint, deve ficar assim:

*br.com.projetoRest.services.ConversorMedidasService.java;*

	@Path("servicos")

	public class ConversorMedidasService {}


Agora vamos criar os métodos que vão ser os endpoint das conversão de distâncias, um vai ser de quilômetros para milhas e outro pra milhas pra quilômetros 

A declaração o método de quilômetros pra milhas fica assim:

*br.com.projetoRest.services.ConversorMedidasService.java*

	// Define qual o verbo http que vai utilizado pra chamar esse método

	@GET

	// Define qual vai ter o url pra acessar o método, sendo o {quilometros} um parâmetro que é quantidade de quilometro que vai ser convertido pra milhas

	@Path("quilometrosParaMilhas/{quilometros}")

	// Metodo que faz um simples conversão de quilometro para milhas

	public Response quilometroParaMilha(@PathParam("quilometros")Double quilometros){

			quilometros = quilometros / 1.6;

			return Response.ok(quilometros).build();

	}



Como podemos ver tem uma annotation @PathParam que pega o parâmetro da url {quilometros} e coloca na variável Double quilometros.

O método faz um simples divisão para saber a quantidade de milhas e retorna uma resposta com status 200(OK) e com o valor da conversão no body da resposta.

O @Path(“quilometrosParaMilhas/{quilometros}”) define qual deve ser o url que vamos acessar pra conseguir o resultado a conversa. O {quilometros} é como fosse um coringa que utilizamos par indicar que vai ser um variável por exemplo pra saber quantas milhas da 3 quilômetros devemos acessar a seguinte url:

http://localhost:8080/ProjetoRest/servicos/quilometrosParaMilhas/3

Agora o método de milhas para quilômetros:

br.com.projetoRest.services.ConversorMedidasService.java

	@GET

	@Path("milhasParaQuilometros/{milhas}")

	// Metodo que faz um simples conversão de milhas para quilometros

	public Response milhasParaQuilometros(@PathParam("milhas")Double milhas)

	{

			milhas = milhas * 1.6;

			return Response.ok(milhas).build();

	}



Esse método não tem muita diferença com o método anterior, o funcionamento é o mesmo o que muda é somente que em vez de divisão é um multiplicação que o método faz.

Então a classe ConversorMedidasService deve ficar da seguinte maneira:

*br.com.projetoRest.services.ConversorMedidasService.java*

	package br.com.projetoRest.services;

	import javax.ws.rs.GET;

	import javax.ws.rs.Path;

	import javax.ws.rs.PathParam;

	import javax.ws.rs.core.Response;

	import br.com.projetoRest.seguranca.Seguro;

	@Path("servicos")

	public class ConversorMedidasService {

	@GET

	@Path("quilometrosParaMilhas/{quilometros}")

	// Metodo que faz um simples conversão de quilometro para milhas

	public Response quilometroParaMilha(@PathParam("quilometros")Double quilometros){

			quilometros = quilometros / 1.6;

			return Response.ok(quilometros).build();

		}

	@GET

	@Path("milhasParaQuilometros/{milhas}")

	// Metodo que faz um simples conversão de milhas para quilometros

	public Response milhasParaQuilometros(@PathParam("milhas")Double milhas){

			milhas = milhas * 1.6;

			return Response.ok(milhas).build();

		}

	}



Agora precisamos configurar o web.xml pra que o jersey possa ser utilizado

o web.xml fica assim:

*/ProjetoRest/WebContent/WEB-INF/web.xml*

	?xml version="1.0" encoding="UTF-8"?>

	<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://xmlns.jcp.org/xml/ns/javaee" xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd" id="WebApp_ID" version="3.1">

	 <display-name>ProjetoRest</display-name>

	 <servlet>

	    <servlet-name>br.com.projetoRest</servlet-name>

	    <servlet-class>org.glassfish.jersey.servlet.ServletContainer</servlet-class>

	     Aqui você define qual vai ser o package que vai conter os endpoint do projeto.

	    <init-param>

	      <param-name>jersey.config.server.provider.packages</param-name>

	      <param-value>br.com.projetoRest</param-value>

	    </init-param>

	    <init-param>

	      <param-name>jersey.config.server.tracing</param-name>

	      <param-value>ALL</param-value>

	    </init-param>

	    <load-on-startup>1</load-on-startup>

	  </servlet>

	  aqui onde vc define qual vai ser a url que o jesery vai escutar pra gerenciar as chamadas

	  <servlet-mapping>

	    <servlet-name>br.com.projetoRest</servlet-name>

	    <url-pattern>/*</url-pattern>

	  </servlet-mapping>

	</web-app>



Com o servidor da aplicação iniciado, podemos abrir o postman e fazer uma chamada GET no seguinte endereço: 

[http://localhost:8080/ProjetoRest/servicos/milhasParaQuilometros/1](http://localhost:8080/ProjetoRest/servicos/milhasParaQuilometros/1)

O resultado tem que ser o seguinte: 

![/milhasParaQuilometros](/assets/0.jpg)

Como pode ver a resposta veio 1,6 que é quantidade de quilômetros que uma milha tem. E o status da resposta 200 OK.

### Login e gerar o JWT

Vamos fazer o endpoint de login no sistema, que vai verificar se credencias do usuário, se for valida será gerado um JWT e retorna esse token pra o cliente, se não for valido retorna um response com status 401 UNAUTHORIZED

Primeiramente vamos criar a classe Credencial no package br.com.projetoRest.model, vai ser um classe simple que representa as credenciais do usuário e vai ter só dois campos o login e a senha e seus getters and setters, a classe vai ficar assim:

*br.com.projetoRest.model.Credencial.java*

	package br.com.projetoRest.model;

	public class Credencial {

		private String login;

		private String senha;	

		// Getters e Setters omitidos 

	}


Agora vamos criar a classe LoginService no package br.com.projetoRest.services. 

Com classe criada vamos definir o @PATH da classe que vai ser “/login”, vai ficar assim:

*br.com.projetoRest.services.LoginService.java*

	@Path("/login")

	public class LoginService {}


Agora vamos criar o método POST que vai ser responsável de fazer o login. O método vai ficar assim:

*br.com.projetoRest.services.LoginService.java*

	// Método POST que valida as credencias enviadas na request 

	// e se for validas retorna o token para o cliente 

	@POST

	// Define que o método espera um objeto to tipo json no corpo da requisição 

	@Consumes(MediaType.APPLICATION_JSON)

	public Response fazerLogin(String credenciaisJson){

		try {

	// Instancia o objeto Gson que vai ser responsável de transformar o corpo da request que está na variável crendenciaisJson em um objeto java Credencial

			Gson gson = new Gson();

	// aqui o objeto gson transforma a crendenciaisJson pra a variavel credencial do tipo Credencial

			Credencial credencial = gson.fromJson(credenciaisJson, Credencial.class);

	// Verifica se a credencial é valida, se não for vai dar exception 

			validarCrendenciais(credencial);

	// Se a credencial gera o token e passa a quantidade de dias que o token vai ser valido nesse caso 1 dia

			String token = gerarToken(credencial.getLogin(),1);

			// Retorna uma resposta com o status 200 OK com o token gerado

			return Response.ok(token).build();

			} catch (Exception e) {

			e.printStackTrace();

		// Caso ocorra algum erro retorna uma resposta com o status 401 UNAUTHORIZED

			return Response.status(Status.UNAUTHORIZED).build();

			}

		}


O método que valida as credencias fica assim:

*br.com.projetoRest.services.LoginService.java*

	private void validarCrendenciais(Credencial crendencial) throws Exception {

	try {

		if(!crendencial.getLogin().equals("teste") || !crendencial.getSenha().equals("123"))

				throw new Exception("Crendencias não válidas!");

	} catch (Exception e) {

			throw e;

		}

	}


Esse método é onde vai fazer a busca na base de dados se existe usuário com esse login e senha, mas como essa uma aplicação simples e sem base dados, so fiz que se o login for diferente de “teste" ou senha diferente de “123" da um exception, aqui vc pode colocar o método de autenticação que sua aplicação utiliza. O método que gera o token fica assim:

*br.com.projetoRest.services.LoginService.java*

	private String gerarToken(String login,Integer expiraEmDias ){

	// Define qual vai ser o algoritmo da assinatura no caso vai ser o HMAC SHA512

	SignatureAlgorithm algoritimoAssinatura = SignatureAlgorithm.HS512;

	// Data atual que data que o token foi gerado

	Date agora = new Date();

	// Define até que data o token é pelo quantidade de dias que foi passo pelo parâmetro expiraEmDias

	Calendar expira = Calendar.getInstance();

	expira.add(Calendar.DAY_OF_MONTH, expiraEmDias);

	// Encoda a frase segredo pra base64 pra ser usada na geração do token 

	byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(FRASE_SEGREDO);

	SecretKeySpec key = new SecretKeySpec(apiKeySecretBytes, algoritimoAssinatura.getJcaName());

	// E finalmente utiliza o JWT builder pra gerar o token

	JwtBuilder construtor = Jwts.builder()

		.setIssuedAt(agora)// Data que o token foi gerado

		.setIssuer(login)// Coloca o login do usuário mais podia qualquer outra informação

		.signWith(algoritimoAssinatura, key)// coloca o algoritmo de assinatura e frase segredo já encodada

		.setExpiration(expira.getTime());//  coloca até que data que o token é valido

		return construtor.compact();// Constrói o token retornando ele como uma String

	}



Nesse método usamos os recursos da biblioteca JJWT para gerar um token que no seu payload vai contem o login do usuário, e que vai expirar depois da quantidade de dias que foi passado. 

Precisamos testar se essa funcionalidade de login está fazendo aquilo que é esperado, para isso vamos no postman fazendo um POST na seguinte url: [http://localhost:8080/ProjetoRest/login](http://localhost:8080/ProjetoRest/login) , passando no corpo da requisição o seguinte objeto credencial no formato JSON:

	{
	  "login": "teste",
	  "senha": "123"
	}


O resultado tem que ser o seguinte: 

![Login válido](/assets/1.jpg)

Como podemos ver o resultado foi o um resposta com o status 200 OK e no corpo da resposta tem o token gerado.

Vamos fazer um teste passando um credencial inválida pra testar se a aplicação realmente não vai retornar o token, vamos enviar agora o seguinte objeto credencial no formato JSON:

	{
	  "login": "teste",
	  "senha": "1234"
	}


O resultado é esse: 

![Login inválido](/assets/2.jpg)

O resultado é que recebemos uma resposta com o status 401 UNAUTHORIZED, sem o token e sim um resposta de erro padrão.

## Autenticação

Com o endpoint de login pronto, precisamos fazer com que possamos proteger nossos endpoint deixando somente quem tem o token válido possa ter acesso.

O token deve ser enviado em nossas requisições através do header padrão do protocolo HTTP o Authorization, então o header ficaria da seguinte forma : Authorization: Bearer <token-goes-here>

O JAX-RS contém o @NameBinding, que é uma meta annotation que é usada pra criar name-binding annotation para filtros e interceptadores, usando isso podemos fazer uma annotation que vai extrair o token do Authorization header e validar o token extraído e vamos dar o nome de @Seguro.

Primeiro vamos criar o package br.com.projetoRest.seguranca e criar a classe Seguro, essa classe vai ficar da seguinte forma:

br.com.projetoRest.seguranca.Seguro.java

	package br.com.projetoRest.seguranca;

	import java.lang.annotation.ElementType;

	import java.lang.annotation.Retention;

	import java.lang.annotation.RetentionPolicy;

	import java.lang.annotation.Target;

	import javax.ws.rs.NameBinding;

	import br.com.projetoRest.model.NivelPermissao;

	@NameBinding

	@Retention(RetentionPolicy.RUNTIME)

	@Target({ElementType.TYPE,ElementType.METHOD})

	public @interface Seguro {}


A annotation @Seguro vai ser usada pra decorar uma classe filtro chamada FiltroAutenticacao, que implementa a classe ContainerRequestContext qual permite manipular a request e assim pegar o header Authorization e extrair o token e validar o mesmo.

Para implementar o filtro vamos criar a classe FiltroAutenticacao dentro do package br.com.projetoRest.seguranca.

A classe vai fica assim:

*br.com.projetoRest.seguranca.FiltroAutenticacao.java*

	package br.com.projetoRest.seguranca;

	import java.io.IOException;

	import java.security.Principal;

	import javax.annotation.Priority;

	import javax.ws.rs.NotAuthorizedException;

	import javax.ws.rs.Priorities;

	import javax.ws.rs.container.ContainerRequestContext;

	import javax.ws.rs.container.ContainerRequestFilter;

	import javax.ws.rs.core.HttpHeaders;

	import javax.ws.rs.core.Response;

	import javax.ws.rs.core.SecurityContext;

	import javax.ws.rs.ext.Provider;

	import br.com.projetoRest.services.LoginService;

	import io.jsonwebtoken.Claims;

	// Define que a @seguro que vai utilizar essa classe

	@Seguro

	// Indica que essa classe vai prover a funcionalidade pra @seguro não o contario

	@Provider

	// E prioridade de execucao, pois podemos ter outras classe filtro

	// que devem ser executas em uma ordem expecifica

	@Priority(Priorities.AUTHENTICATION)

	public class FiltroAutenticacao implements ContainerRequestFilter{

	// Aqui fazemos o override do método filter que tem como parâmetro

	//  o ContainerRequestContext que é o objeto que podemos manipular a request

	@Override

	public void filter(ContainerRequestContext requestContext) throws IOException {

		// Verifica se o header AUTHORIZATION existe ou não se existe extrai o token 

		// se não aborta a requisição retornando uma NotAuthorizedException

	String authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);

		if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {

			throw new NotAuthorizedException("Authorization header precisa ser provido");

		}

		// extrai o token do header

		String token = authorizationHeader.substring("Bearer".length()).trim();

		// verificamos se o método é valido ou não

		// se não for valido a requisição é abortada e retorna uma resposta com status 401 UNAUTHORIZED

		// se for valida modificamos o o SecurityContext da request 

		// para que quando usarmos o getUserPrincipal retorne o login do usuario 

		try {

			//  método que verifica se o token é valido ou não 

			Claims claims = new LoginService().validaToken(token);

			// Caso não for valido vai retornar um objeto nulo e executar um exception

			if(claims==null)

				throw new Exception("Token inválido");

			// Método que modifica o SecurityContext pra disponibilizar o login do usuario

			modificarRequestContext(requestContext,claims.getId());

			} catch (Exception e) {

			e.printStackTrace();

			// Caso o token for invalido a requisição é abortada e retorna uma resposta com status 401 UNAUTHORIZED

			requestContext.abortWith(

				Response.status(Response.Status.UNAUTHORIZED).build());

			}

		}

		// Método que modifica o SecurityContext

	private void modificarRequestContext(ContainerRequestContext requestContext,String login){

		final SecurityContext currentSecurityContext = requestContext.getSecurityContext();

		requestContext.setSecurityContext(new SecurityContext() {

			 @Override

			 public Principal getUserPrincipal() {

			    return new Principal() {

			      @Override

			      public String getName() {

			        return login;

			      }

			    };

			  }

			  @Override

			  public boolean isUserInRole(String role) {

			    return true;

			  }

			  @Override

			  public boolean isSecure() {

			    return currentSecurityContext.isSecure();

			  }

			  @Override

			  public String getAuthenticationScheme() {

			    return "Bearer";

			  }

			});

		}

	}


Na classe LoginService precisos fazer o método validaToken que vai validar os token JWT, a biblioteca JJWT ja disponibiliza algumas funcionalidade pra facilitar esse processo, método fica assim:

*br.com.projetoRest.services.LoginService.java*

	public Claims validaToken(String token) {

		try{

		   // JJWT vai validar o token caso o token não seja valido ele vai executar uma exeption

		   // o JJWT usa a frase segredo pra descodificar o token e ficando assim possivel

		   // recuperar as informações que colocamos no payload

		   Claims claims = Jwts.parser()     

			     .setSigningKey(DatatypeConverter.parseBase64Binary(FRASE_SEGREDO))

				.parseClaimsJws(token).getBody();

				// Aqui é um exemplo que se o token for valido e descodificado 

				// vai imprimir o login que foi colocamos no token

				System.out.println(claims.getIssuer());

		  return claims;

		}catch(Exception ex){

				throw ex;

		}

	}


Com a validação do token podemos utilizar o @Seguro nos métodos que queremos deixar disponíveis so pra usuários autenticados. Vamos pegar o método de quilômetros para milhas do ConversorMedidasService com exemplo. Fica assim:

*br.com.projetoRest.service.ConversorMedidasService.java*

	@Seguro

	@GET

	@Path("quilometrosParaMilhas/{quilometros}")

	// Metodo que faz um simples conversão de quilometro para milhas

	public Response quilometroParaMilha(@PathParam("quilometros")Double quilometros){

		quilometros = quilometros / 1.6;

		return Response.ok(quilometros).build();

	}


A única diferença é que temos a annotation @Seguro decorando o método, para testar se a autenticação está funcionando, vamos chamar o método pelo PostMan. O resultado é o seguinte: 

![3](/assets/3.jpg)

Recebemos um resposta de 401 Unauthorized, que é o certo já que não passamos nenhum token para aplicação validar, agora vamos passar o token que conseguimos através do endpoint de login e colocar o token no header Authorization na hora de fazer a chamada pra aplicação.

Lembrando o que o header Authorization tem que começar com Bearer e depois o token. Fica assim o resultado: 

![4](/assets/4.jpg)

Resultado foi a resposta com o valor da conversão e o status 200 OK indicando que deu tudo certo com a requisição.

## Considerações

Os métodos que não forem decorados com o @Seguro, não vão ser protegidos e vai ficar disponíveis pra qualquer requisição tendo ela um token válido ou não.

Classes também podem ser decoradas com a annotation @Seguro , fazendo que todos os seus métodos protegidos sem a necessidade de colocar o annotation em cada um deles.

## Implementar autorização por nível de acesso

No JAX-RS nós permite fazer que os métodos tenham diferentes níveis de acesso, com isso o usuário além de possuir um token valido também é preciso que ele tenha o nível de permissão necessário para aquele método que ele deseja executar.

Para começar a fazer essa implementação, vamos criar uma classe enum NivelPermissao no package br.com.projetoRest.model, que vai conter o níveis de permissão da aplicação:

*br.com.projetoRest.model.NivelPermissao.java*

	package br.com.projetoRest.model;

	public enum NivelPermissao {

		NIVEL_1,NIVEL_2,NIVEL_3

	}


Classe NivelPermissao feita, precisamos altura a classe Seguro pra que ele possa receber os níveis de permissão:

*br.com.projetoRest.seguranca.Seguro.java*

	@NameBinding

	@Retention(RetentionPolicy.RUNTIME)

	@Target({ElementType.TYPE,ElementType.METHOD})

	public @interface Seguro { 

		NivelPermissao[] value() default{};

	}


Com essa mudança, o @seguro pode receber um array com níveis de permissão que queremos. 

Exemplo: `@Seguro({NivelPermissao.NIVEL_1,NivelPermissao.NIVEL_2})`

Para fazer que a annotation @Seguro consigo fazer esse controle, vamos criar um classe chamada FiltroAutorizacao que implementa o ContainerRequestFilter igual o FiltroAutenticacao.

A classe FiltroAutorizacao vai pegar os níveis de permissão que está defino no @Seguro que está no método ou na classe e verificar se o usuário tem esse nível de permissão, se tiver a requisição continua normalmente, se não tiver retorna um resposta com o status 403 FORBIDDEN.

Vale frisar que o @Seguro do método sobrepõe o @Seguro da classe, então se classe o @Seguro tiver o nível de acesso Nivel_1 e método tiver Nivel_2, o método so vai ser acessível a usuário que tiver o Nivel_2.

O FiltroAutorizacao vai ser sempre executado depois do FiltroAutenticacao, isso é definido pelo @Priority(). A ordem que o JAX-RS executa é de acordo com o @Priority. 

Dito isso a classe FiltroAutorizacao fica dessa forma:

*br.com.projetoRest.seguranca.FiltroAutorizacao.java*

	package br.com.projetoRest.seguranca;

	import java.io.IOException;

	import java.lang.reflect.AnnotatedElement;

	import java.lang.reflect.Method;

	import java.util.ArrayList;

	import java.util.Arrays;

	import java.util.List;

	import javax.annotation.Priority;

	import javax.ws.rs.container.ContainerRequestContext;

	import javax.ws.rs.container.ContainerRequestFilter;

	import javax.ws.rs.container.ResourceInfo;

	import javax.ws.rs.core.Context;

	import javax.ws.rs.core.Response;

	import javax.ws.rs.ext.Provider;

	import br.com.projetoRest.model.NivelPermissao;

	import br.com.projetoRest.services.LoginService;

	import javax.ws.rs.Priorities;

	// Define que a @seguro que vai utilizar essa classe

	@Seguro

	// Indica que essa classe vai prover a funcionalidade pra @seguro não o contrario

	@Provider

	// E prioridade de execução, pois podemos ter outras classe filtro

	// que devem ser executas em uma ordem específica

	// Nesse caso vai ser executada depois do FiltroAutenticacao,

	// pois a prioridade AUTHENTICATION é maio que o do AUTHORIZATION

	@Priority(Priorities.AUTHORIZATION)

	public class FiltroAutorizacao implements ContainerRequestFilter {

	// O JAX-RS faz a injeção do ResourceInfo que vai ter os informações do método que ta sendo verificado 

		@Context

		private ResourceInfo resourceInfo;

		@Override

		public void filter(ContainerRequestContext requestContext) throws IOException {

			//  Pega a classe que contem URL requisitada e extrai os nível de permissão dela

			Class<?// classe = resourceInfo.getResourceClass();

			List<NivelPermissao// nivelPermissaoClasse = extrairNivelPermissao(classe);

			//  Pega o método que contem URL requisitada e extrai os nível de permissão dele

			Method metodo = resourceInfo.getResourceMethod();

			List<NivelPermissao// nivelPermisaoMetodo = extrairNivelPermissao(metodo);

			try {

		// Como modificamos o securityContext na hora de validar o token, para podemos pegar

		// O login do usuário, para fazer a verificação se ele tem o nível de permissão necessário

		// para esse endpoint

			String login = requestContext.getSecurityContext().getUserPrincipal().getName();

				//  Verifica se o usuário tem permissão pra executar esse método

				//  Os níveis de acesso do método sobrepõe o da classe

				if (nivelPermisaoMetodo.isEmpty()) {

					checarPermissoes(nivelPermissaoClasse,login);

				} else {

					checarPermissoes(nivelPermisaoMetodo,login);

				}

			} catch (Exception e) {

				// Se caso o usuário não possui permissão é dado um exception, 

				// e retorna um resposta com o status 403 FORBIDDEN 

				requestContext.abortWith(

						Response.status(Response.Status.FORBIDDEN).build());

			}

		}

		// Método que extrai os níveis de permissão que foram definidos no @Seguro

		private List<NivelPermissao// extrairNivelPermissao(AnnotatedElement annotatedElement) {

			if (annotatedElement == null) {

				return new ArrayList<NivelPermissao>();

			} else {

				Seguro seguro = annotatedElement.getAnnotation(Seguro.class);

				if (seguro == null) {

					return new ArrayList<NivelPermissao>();

				} else {

					NivelPermissao[] niveisPermitidos = seguro.value();

					return Arrays.asList(niveisPermitidos);

				}

			}

		}
	// Verifica se o usuário tem permissão pra executar o método, se não for definido nenhum nível de acesso no @Seguro,Então todos vão poder executar desde que possuam um token valido

	private void checarPermissoes(List<NivelPermissao// nivelPermissaoPermitidos,String login) throws Exception {

		try {

			if(nivelPermissaoPermitidos.isEmpty())

				return;

			boolean temPermissao = false;

			// Busca quais os níveis de acesso o usuário tem.

			NivelPermissao nivelPermissaoUsuario = new 		LoginService().buscarNivelPermissao(login);

			for (NivelPermissao nivelPermissao : nivelPermissaoPermitidos) {

				if(nivelPermissao.equals(nivelPermissaoUsuario))

				{

					temPermissao = true;

					break;

				}

			}

			if(!temPermissao)

			throw new Exception("Cliente não possui o nível de permissão para esse método");

			} catch (Exception e) {

				e.printStackTrace();

				throw e;

			}

		}



	}


No LoginService tem o método que busca o níveis de permissão de um usuário, como nosso foco é a autenticação, vai ser um método simples que so retorna um nível de acesso independente do usuário, mas na sua aplicação vc pode implementar um método mais complexo que você precisa. O método fica assim:

*br.com.projetoRest.services.LoginService.java*

	// Método simples como não usamos banco de dados e foco é o parte autenticação

	// o método retorna somente um nível de acesso, mas em uma aplicação normal

	// aqui seria feitor a verificação de que níveis de permissão o usuário tem e retornar eles

	public NivelPermissao buscarNivelPermissao(String login) {

		return NivelPermissao.NIVEL_1;

	}


Vamos modificar os métodos da classe ConversorMedidasService quilometroParaMilha e milhasParaQuilometros para que o @Seguro deles tenham os níveis de permissões no método vamos colocar o NivelPermissao.Nivel_1 e no método milhasParaQuilometros o NívelPermissao.Nivel_2.

Com a modificação os métodos ficam assim:

	@Seguro({NivelPermissao.NIVEL_1})

	@GET

	@Path("quilometrosParaMilhas/{quilometros}")

	// Método que faz um simples conversão de quilometro para milhas

	public Response quilometroParaMilha(@PathParam("quilometros")Double quilometros){

		quilometros = quilometros / 1.6;

		return Response.ok(quilometros).build();

	}

	@Seguro({NivelPermissao.NIVEL_2})

	@GET

	@Path("milhasParaQuilometros/{milhas}")

	// Método que faz um simples conversão de milhas para quilômetros

	public Response milhasParaQuilometros(@PathParam("milhas")Double milhas){

		milhas = milhas * 1.6;

		return Response.ok(milhas).build();

	}


Como o método que busca o nível de permissão do usuário sempre vai retornar o NivelPermissao.Nivel_1, o método quilometroParaMilha vai retornar um resposta 200 Ok com o valor da conversão. 

O método milhasParaQuilometros que precisa do nível de acesso NívelPermissao.Nivel_2 vai retornar um resposta com o status 403 FORBIDDEN

Como mostrado nesses resultados do PostMan:

**Quilômetro Para Milha:** 

![5](/assets/5.jpg)

**Milha pra Quilômetro:** 

![6](/assets/6.jpg)


## Considerações finais

Nesse tutorial explicou como funciona autenticação baseada em token e mostra passo a passo como fazer a autenticação baseada em token com um projeto java.

Lembrando que não importe o tipo de autenticação que você escolher sempre devemos utilizar uma conexão HTTPS, que assim garantimos a segurança da aplicação.


## Referências 

The Ins and Outs of Token Based Authentication- [https://scotch.io/tutorials/the-ins-and-outs-of-token-based-authentication](https://scotch.io/tutorials/the-ins-and-outs-of-token-based-authentication)

JSON Web Token - JWT - [https://blog.lucaskatayama.com/posts/2016/03/30/JSON-Web-Token-JWT/#sthash.32ThI6IT.dpbs](https://blog.lucaskatayama.com/posts/2016/03/30/JSON-Web-Token-JWT) 

JSON Web Tokens - [http://jwt.io](http://jwt.io)

Man in the middle - [https://en.wikipedia.org/wiki/Man-in-the-middle_attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)

Token Based Authentication for Single Page Apps (SPAs)- [https://stormpath.com/blog/token-auth-spa](https://stormpath.com/blog/token-auth-spa)

Token-based authentication - Securing the token -[https://security.stackexchange.com/questions/19676/token-based-authentication-securing-the-token](https://security.stackexchange.com/questions/19676/token-based-authentication-securing-the-token)

Resposta do usuario  [Cássio Mazzochi Molin](https://stackoverflow.com/users/1426227/c%c3%a1ssio-mazzochi-molin) - [https://stackoverflow.com/a/26778123](https://stackoverflow.com/a/26778123)