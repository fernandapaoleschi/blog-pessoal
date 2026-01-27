import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';
import { TypeOrmModule } from '@nestjs/typeorm';

describe('Testes dos Módulos Usuario e Auth (e2e)', () => {

  let app: INestApplication;
  let token: string;
  let usuarioId: number;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: 'sqlite',
          database: ':memory:',
          entities: [__dirname + '/../src/**/entities/*.entity{.ts,.js}'],
          synchronize: true,
          dropSchema: true,
        }),
        AppModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('01 - Deve cadastrar um novo usuário', async () => {
    const resposta = await request(app.getHttpServer())
      .post('/usuarios/cadastrar')
      .send({
        nome: 'Root',
        usuario: 'root@root.com',
        senha: '07010701',
        foto: 'https://i.imgur.com/foto.png',
      })
      .expect(201);

    usuarioId = resposta.body.id;
  });

  it('02 - Não deve cadastrar usuário duplicado', async () => {
    await request(app.getHttpServer())
      .post('/usuarios/cadastrar')
      .send({
        nome: 'Root',
        usuario: 'root@root.com',
        senha: '07010701',
        foto: 'https://i.imgur.com/foto.png',
      })
      .expect(400);
  });

it('03 - Deve autenticar o usuário (login)', async () => {
  const resposta = await request(app.getHttpServer())
    .post('/auth/logar')
    .send({
      usuario: 'root@root.com',
      senha: '07010701',
    })
    .expect(200);

  token = resposta.body.token;
});

it('04 - Deve listar todos os usuários', async () => {
  await request(app.getHttpServer())
    .get('/usuarios/all')
    .set('Authorization', token)
    .expect(200);
});

it('05 - Deve atualizar um usuário', async () => {
  await request(app.getHttpServer())
    .put('/usuarios/atualizar')
    .set('Authorization', token)
    .send({
      id: usuarioId,
      nome: 'Root Atualizado',
      usuario: 'root@root.com',
      senha: '07010701',
      foto: 'https://i.imgur.com/foto.png',
    })
    .expect(200)
    .then(resposta => {
      expect(resposta.body.nome).toBe('Root Atualizado');
    });
});

});
