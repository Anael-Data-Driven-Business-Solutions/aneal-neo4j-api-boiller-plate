const { Neo4jGraphQL } = require('@neo4j/graphql');
const { OGM } = require('@neo4j/graphql-ogm');
const { Neo4jGraphQLAuthJWTPlugin } = require('@neo4j/graphql-plugin-auth');
const { ApolloServer } = require('apollo-server');
const {
  ApolloServerPluginLandingPageGraphQLPlayground,
} = require('apollo-server-core');
const neo4j = require('neo4j-driver');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const jwt_decode = require('jwt-decode');

// Configure dotenv
dotenv.config();

let token = null;

// Create Neo4j driver
const driver = neo4j.driver(
  'bolt://137.184.2.210:7687',
  neo4j.auth.basic('neo4j', 'letmein')
);

//Create JWT payload
function createJWT(user_name) {
  // Create token
  token = jwt.sign(
    { user_id: user_name },
    process.env.NEO4J_GRAPHQL_JWT_SECRET,
    {
      expiresIn: '2h',
    }
  );

  return token;
}

// Compare password with that in the database
const comparePassword = (user_password, hash) => {
  return bcrypt.compareSync(user_password, hash);
};

const typeDefs = `
    type User {
        id: ID @id
        user_name: String @unique
        user_password: String! @private
        user_email: String! @unique
        user_is_admin: Boolean
    }

    type Product{
   id: ID @id
   product_brand: String!
   product_category: String!
   product_count_in_stock: Int!
   product_description: String!
   product_image: String!
   product_name: String!
   product_number_of_reviews: Int!
   product_price: Float!
   product_rating:Float!
   product_slug: String!

   product_creator: User @relationship(type: "USER_CREATED_PRODUCT", direction: IN)
}

    type Mutation {
        signUp(user_name: String!, user_email: String!, user_password: String!): String! ### JWT
        signIn(user_name: String!, user_password: String!): String! ### JWT
    }
`;

// Create OGM instance
const ogm = new OGM({ typeDefs, driver });

// Create user model
const User = ogm.model('User');

async function signUp(_source, { user_name, user_email, user_password }) {
  const emailRegexp =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  const [usernameExisting] = await User.find({
    where: {
      user_name,
    },
  });

  const [emailExisting] = await User.find({
    where: {
      user_email,
    },
  });

  const isValidEmail = emailRegexp.test(user_email);

  if (!isValidEmail) {
    throw new Error(`Invalid Email Address!`);
  }

  if (usernameExisting) {
    throw new Error(`User with username ${user_name} already exists!`);
  }

  if (emailExisting) {
    throw new Error(`User with email ${user_name} already exists!`);
  }

  const hashedPassword = await bcrypt.hash(user_password, 10);

  const { users } = await User.create({
    input: [
      {
        user_name,
        user_email,
        user_password: hashedPassword,
      },
    ],
  });

  return createJWT(users[0].user_name);
}

async function signIn(_source, { user_name, user_password }) {
  const [user] = await User.find({
    where: {
      user_name,
    },
  });

  if (!user) {
    throw new Error(`User with user_name ${user_name} not found!`);
  }

  const correctPassword = await comparePassword(
    user_password,
    user.user_password
  );

  if (!correctPassword) {
    throw new Error(`Incorrect username or password!`);
  }

  return createJWT(user.user_name);
}

// Create resolver
const resolvers = {
  // Mutation resolvers

  Mutation: {
    signUp,
    signIn,
  },
};

const neoSchema = new Neo4jGraphQL({
  typeDefs,
  driver,
  resolvers,
  plugins: {
    auth: new Neo4jGraphQLAuthJWTPlugin({
      secret: process.env.NEO4J_GRAPHQL_JWT_SECRET,
    }),
  },
});

Promise.all([neoSchema.getSchema(), ogm.init()]).then(([schema]) => {
  const server = new ApolloServer({
    schema,
    context: ({ req }) => ({ req }),
    plugins: [ApolloServerPluginLandingPageGraphQLPlayground()],
  });

  server.listen().then(({ url }) => {
    console.log(`🚀 Server ready at ${url}`);
  });
});
