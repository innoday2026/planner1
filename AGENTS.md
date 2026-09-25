# AGENTS.md — Auth & Identity Service

## 1. Stack

| Technology | Role |
|---|---|
| **Node.js 20 LTS** | Runtime |
| **NestJS 10 (TypeScript 5)** | Application framework — modules, DI, guards, interceptors, pipes |
| **Passport.js** | Authentication middleware — `passport-local`, `passport-google-oauth20`, `passport-microsoft`, `passport-oauth2`, `openid-client` (PKCE) |
| **jsonwebtoken** | JWT signing/verification (RS256 asymmetric) |
| **jwks-rsa** | JWKS endpoint key fetching and key rotation support |
| **argon2** | Primary password hashing (fallback migration path from bcrypt) |
| **bcrypt** | Legacy hash comparison during migration |
| **PostgreSQL 15** | Primary store — users, roles, organizations, refresh tokens |
| **TypeORM 0.3** | ORM — entities, migrations, repositories |
| **Redis 7** | Token blacklist (TTL-matched), RBAC permission cache (5-min TTL) |
| **ioredis** | Redis client |
| **class-validator / class-transformer** | DTO validation and transformation |
| **Winston + nest-winston** | Structured JSON logging for security audit events |
| **Helmet** | HTTP security headers |
| **rate-limiter-flexible** | Per-IP and per-user brute-force protection |
| **Jest + Supertest** | Unit and e2e testing |
| **Docker / docker-compose** | Local development and CI environment |
| **GitHub Actions** | CI pipeline |

---

## 2. Project Structure

```
auth-service/
├── AGENTS.md                          # This file
├── tasks.md                           # Agent-generated task checklist (created before coding)
├── .env.example                       # All required env vars documented, no secrets
├── .env                               # Local secrets — never committed
├── .eslintrc.js                       # ESLint config (airbnb-typescript + prettier)
├── .prettierrc                        # Prettier config
├── tsconfig.json                      # Base TypeScript config (strict: true)
├── tsconfig.build.json                # Build config (excludes tests)
├── jest.config.ts                     # Jest config — unit + e2e projects
├── package.json
├── Dockerfile                         # Multi-stage production image
├── docker-compose.yml                 # Local dev: app + postgres + redis
├── docker-compose.test.yml            # CI: ephemeral postgres + redis
├── .github/
│   └── workflows/
│       └── ci.yml                     # Lint → test → build → scan pipeline
├── keys/
│   ├── private.pem                    # RS256 private key (gitignored; injected via secret)
│   └── public.pem                     # RS256 public key (gitignored; injected via secret)
├── migrations/                        # TypeORM migration files (auto-named timestamps)
│   └── .gitkeep
├── src/
│   ├── main.ts                        # Bootstrap: Helmet, global pipes, Swagger, CORS
│   ├── app.module.ts                  # Root module — imports all feature modules
│   ├── config/
│   │   ├── app.config.ts              # NestJS ConfigModule schema (Joi validation)
│   │   ├── database.config.ts         # TypeORM DataSource options factory
│   │   ├── redis.config.ts            # ioredis connection options factory
│   │   └── jwt.config.ts             # RS256 key loading, token TTLs
│   ├── common/
│   │   ├── decorators/
│   │   │   ├── current-user.decorator.ts   # @CurrentUser() param decorator
│   │   │   ├── roles.decorator.ts          # @Roles(...) metadata decorator
│   │   │   └── public.decorator.ts         # @Public() bypass guard decorator
│   │   ├── filters/
│   │   │   └── http-exception.filter.ts    # Global error response shaping
│   │   ├── guards/
│   │   │   ├── jwt-auth.guard.ts           # Global JWT guard (checks blacklist)
│   │   │   └── roles.guard.ts              # RBAC guard using cached permissions
│   │   ├── interceptors/
│   │   │   └── audit-log.interceptor.ts    # Logs auth events via Winston
│   │   ├── pipes/
│   │   │   └── validation.pipe.ts          # Global class-validator pipe
│   │   └── types/
│   │       ├── jwt-payload.interface.ts    # { sub, email, orgId, roles, jti, iat, exp }
│   │       └── request-with-user.interface.ts
│   ├── database/
│   │   ├── database.module.ts         # TypeORM forRootAsync
│   │   └── data-source.ts             # Standalone DataSource for CLI migrations
│   ├── redis/
│   │   ├── redis.module.ts            # Global ioredis provider
│   │   └── redis.service.ts           # get/set/del/ttl wrappers
│   ├── users/
│   │   ├── users.module.ts
│   │   ├── users.controller.ts        # Profile CRUD, org-admin user management
│   │   ├── users.service.ts           # Business logic — create, find, update, deactivate
│   │   ├── users.repository.ts        # TypeORM custom repository
│   │   ├── entities/
│   │   │   └── user.entity.ts         # id, email, passwordHash, orgId, isActive, createdAt
│   │   └── dto/
│   │       ├── create-user.dto.ts
│   │       ├── update-profile.dto.ts
│   │       └── user-response.dto.ts   # Excludes passwordHash via @Exclude()
│   ├── organizations/
│   │   ├── organizations.module.ts
│   │   ├── organizations.controller.ts
│   │   ├── organizations.service.ts
│   │   ├── entities/
│   │   │   └── organization.entity.ts # id, name, domain, createdAt
│   │   └── dto/
│   │       ├── create-organization.dto.ts
│   │       └── organization-response.dto.ts
│   ├── roles/
│   │   ├── roles.module.ts
│   │   ├── roles.service.ts           # Assign/revoke roles, permission lookup
│   │   ├── roles.repository.ts
│   │   ├── entities/
│   │   │   ├── role.entity.ts         # id, name (Admin|Manager|Member|Viewer), orgId
│   │   │   └── user-role.entity.ts    # userId, roleId, orgId — scoped assignment
│   │   └── constants/
│   │       └── roles.enum.ts          # export enum Role { Admin, Manager, Member, Viewer }
│   ├── auth/
│   │   ├── auth.module.ts             # Imports PassportModule, JwtModule, strategies
│   │   ├── auth.controller.ts         # /auth/* endpoints
│   │   ├── auth.service.ts            # Orchestrates login, register, refresh, revoke
│   │   ├── token/
│   │   │   ├── token.service.ts       # Issue access/refresh tokens, rotation, blacklist
│   │   │   └── refresh-token.entity.ts # id, userId, jti, expiresAt, revokedAt
│   │   ├── strategies/
│   │   │   ├── local.strategy.ts      # passport-local — email + argon2 verify
│   │   │   ├── jwt.strategy.ts        # passport-jwt — RS256, checks Redis blacklist
│   │   │   ├── google.strategy.ts     # passport-google-oauth20 — OIDC
│   │   │   └── microsoft.strategy.ts  # openid-client — PKCE, Azure AD
│   │   ├── dto/
│   │   │   ├── register.dto.ts
│   │   │   ├── login.dto.ts
│   │   │   ├── refresh-token.dto.ts
│   │   │   └── token-response.dto.ts  # { accessToken, refreshToken, expiresIn }
│   │   └── events/
│   │       └── auth-event.enum.ts     # LOGIN, LOGOUT, REGISTER, REFRESH, SSO_LOGIN, REVOKE
│   ├── jwks/
│   │   ├── jwks.module.ts
│   │   ├── jwks.controller.ts         # GET /.well-known/jwks.json
│   │   └── jwks.service.ts            # Builds JWK set from public.pem, handles rotation
│   └── health/
│       ├── health.module.ts
│       └── health.controller.ts       # GET /health — DB + Redis liveness
└── test/
    ├── jest-e2e.config.ts
    ├── app.e2e-spec.ts                # Full auth flow e2e
    ├── auth/
    │   ├── auth.e2e-spec.ts           # Register → login → refresh → revoke
    │   └── sso.e2e-spec.ts            # Google/Microsoft OAuth mock flows
    └── fixtures/
        ├── user.fixture.ts
        └── organization.fixture.ts
```

---

## 3. Required Workflow

The agent **must** follow these steps in order. Do not skip or reorder.

### Step 1 — Read All Specifications
- Read this `AGENTS.md` in full before writing any code.
- Read any linked story files or acceptance criteria documents.
- Identify all ambiguities; resolve them using the constraints in Section 7 before proceeding.

### Step 2 — Create `tasks.md`
Create `tasks.md` at the project root with a checkbox list derived from the spec. Example structure:

```markdown
# tasks.md
## Setup
- [ ] Initialise NestJS project with `nest new`
- [ ] Configure TypeScript strict mode
- [ ] Add all dependencies from stack table

## Entities & Migrations
- [ ] Create User entity + migration
- [ ] Create Organization entity + migration
- [ ] Create Role / UserRole entities + migration
- [ ] Create RefreshToken entity + migration

## Feature Modules
- [ ] Config module with Joi schema validation
- [ ] Redis module (global)
- [ ] Users module (CRUD + profile)
- [ ] Organizations module
- [ ] Roles module with Redis caching
- [ ] Auth module (local strategy, JWT, refresh rotation)
- [ ] SSO strategies (Google, Microsoft, PKCE)
- [ ] JWKS endpoint
- [ ] Health endpoint

## Security & Cross-Cutting
- [ ] Global JWT guard with blacklist check
- [ ] RBAC guard using cached permissions
- [ ] Audit log interceptor (all auth events)
- [ ] Rate limiter (login, register endpoints)
- [ ] Helmet + CORS configuration

## Testing
- [ ] Unit tests ≥ 90% coverage for all services
- [ ] E2E tests for full auth flows

## Docker & CI
- [ ] Dockerfile (multi-stage)
- [ ] docker-compose.yml
- [ ] GitHub Actions ci.yml
```

Tick each checkbox (`[x]`) as tasks are completed.

### Step 3 — Implement in Dependency Order
1. Project bootstrap (`nest new`, tsconfig, eslint, prettier)
2. Config module → Database module → Redis module
3. Entities → generate and run migrations
4. Users module → Organizations module → Roles module
5. Token service → Auth strategies → Auth module
6. JWKS module → Health module
7. Guards, interceptors, filters (global registration in `main.ts`)
8. Rate limiting, Helmet, CORS in `main.ts`

### Step 4 — Write Tests Alongside Each Module
- Write unit tests immediately after each service/guard/strategy is implemented.
- Do not batch all tests at the end.
- Run `jest --coverage` after each module; fix failures before moving on.

### Step 5 — Validate
```bash
npm run lint          # Zero ESLint errors
npm run test          # All unit tests pass, ≥ 90% coverage
npm run test:e2e      # All e2e tests pass against docker-compose.test.yml
npm run build         # tsc compiles with zero errors
docker build -t auth-service:local .   # Image builds successfully
```

Only mark a task complete after all five commands succeed.

---

## 4. Coding Conventions

### General
- **TypeScript strict mode** (`strict: true`, `noImplicitAny`, `strictNullChecks`). No `any` types — use `unknown` and narrow explicitly.
- All files use **named exports** only; no default exports.
- One class per file. File name matches class name in kebab-case: `token.service.ts` → `TokenService`.

### NestJS Patterns
- Every feature is a **self-contained NestJS module**. Cross-module communication only via injected services, never direct entity access across modules.
- Use `forRootAsync` / `forFeatureAsync` with factory functions for all dynamic modules (TypeORM, Redis, JWT).
- **Never** put business logic in controllers. Controllers validate input (DTO pipes), call one service method, return the result.
- Use `@UseGuards(JwtAuthGuard, RolesGuard)` explicitly on controller methods that require RBAC. The global `JwtAuthGuard` can be bypassed with `@Public()`.
- All controller responses must use typed response DTOs with `@Exclude()` on sensitive fields and `ClassSerializerInterceptor` globally enabled.

### Naming Conventions
| Artefact | Convention | Example |
|---|---|---|
| Files | kebab-case | `auth.service.ts` |
| Classes | PascalCase | `AuthService` |
| Interfaces | PascalCase + `Interface` suffix | `JwtPayloadInterface` |
| Enums | PascalCase | `Role`, `AuthEvent` |
| Constants | SCREAMING_SNAKE_CASE | `ACCESS_TOKEN_TTL` |
| Env vars | SCREAMING_SNAKE_CASE | `JWT_PRIVATE_KEY_PATH` |
| DB columns | snake_case (TypeORM `@Column({ name: 'column_name' })`) | `created_at` |
| REST routes | kebab-case, plural nouns | `/auth/refresh-token` |

### Security Patterns
- **Never** log raw passwords, tokens, or PII. Log only `userId`, `orgId`, `jti`, event type, and timestamp.
- Access tokens: RS256, 15-minute TTL, claims `{ sub, email, orgId, roles, jti }`.
- Refresh tokens: stored as hashed value (argon2) in PostgreSQL with `jti`, `expiresAt`, `revokedAt`.
- On refresh: verify stored token → issue new pair → immediately revoke old `jti` in Redis blacklist AND mark DB record `revokedAt`.
- JWKS key rotation: support at least two simultaneous public keys (`kid` header). Old key retained for `accessTokenTTL` duration after rotation.
- All argon2 hashing uses `argon2.hash(password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 })`.
- PKCE (`code_challenge_method=S256`) enforced for all mobile OAuth flows via `openid-client`.

### Database
- All schema changes via **TypeORM migrations only**. Never use `synchronize: true` in any environment.
- Entities use UUIDs (`@PrimaryGeneratedColumn('uuid')`).
- Soft deletes via `@DeleteDateColumn()` on User and Organization entities.
- All foreign keys have explicit `onDelete` behaviour defined.
- Index all columns used in `WHERE` clauses: `user.email`, `user.orgId`, `refresh_token.jti`, `user_role.userId`.

### Redis Usage
- Blacklist key pattern: `blacklist:jti:{jti}