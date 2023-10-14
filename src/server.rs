use std::io::{Read, Write};

#[macro_use]
extern crate log;

#[macro_use]
mod util;

#[macro_export]
macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + $crate::count!($($xs)*));
}

macro_rules! iterable_enum {
    ($(#[$derives:meta])* $(vis $visibility:vis)? enum $name:ident { $($(#[$nested_meta:meta])* $member:ident),* }) => {
        const COUNT_MEMBERS:usize = $crate::count!($($member)*);
        $(#[$derives])*
        $($visibility)? enum $name {
            $($(#[$nested_meta])* $member),*
        }
        impl $name {
            pub const fn iter() -> [$name; COUNT_MEMBERS] {
                [$($name::$member,)*]
            }
        }
    };
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Config {
    pool_id: usize,
    peers: Vec<String>,
}

impl Config {
    fn init_pool_id(&mut self, stream: &mut std::net::TcpStream) {
        let mut pool_id_str = String::new();
        stream
            .read_to_string(&mut pool_id_str)
            .expect(&format!("{}: read_to_string failed", function!()));
        self.pool_id = pool_id_str
            .parse()
            .expect(&format!("{}: parse failed", pool_id_str));
    }

    fn init_peers(&mut self, stream: &mut std::net::TcpStream) {
        let mut peers_str = String::new();
        stream
            .read_to_string(&mut peers_str)
            .expect(&format!("{}: read_to_string failed", function!()));
        self.peers = peers_str.split_whitespace().map(str::to_string).collect();
    }

    fn validate(&self) {
        let peer_count = self.peers.len();
        if peer_count < 1 {
            panic!("{}: peer addresses are missing", function!());
        }
        if peer_count < 2 {
            panic!("{}: single peer replica not allowed", function!());
        }
        if peer_count % 2 == 0 {
            panic!("{}: peer count must be odd", function!());
        }
    }

    fn init(&mut self) {
        let (mut stream, _) = std::net::TcpListener::bind("0.0.0.0:6789")
            .expect(&format!("{}: bind failed", function!()))
            .accept()
            .expect(&format!("{}: accept failed", function!()));
        self.init_pool_id(&mut stream);
        self.init_peers(&mut stream);
        self.validate();
        info!(
            "{}: \n{}",
            function!(),
            serde_json::to_string_pretty(&self).unwrap()
        );
    }
}
//
// #[derive(serde::Serialize, serde::Deserialize)]
// struct Consensus {}
//
// impl Consensus {
//     fn commit(&mut self, request: &String) {}
//
//     fn init(&mut self) {}
// }

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone)]
enum TokenT {
    Eq,
    NotEq,
    Greater,
    Less,
    GreaterEq,
    LessEq,
    Comma,
    Dot,
    Num,
    Ident,
    Whitespace,
    Error,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Token {
    token_t: TokenT,
    val: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq)]
enum StatementT {
    Insert,
    Select,
    Update,
    Error,
}

iterable_enum! {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq)]
    vis pub(crate) enum Keyword {
        All,
        And,
        Any,
        As,
        Between,
        By,
        Case,
        Cast,
        Char,
        Check,
        Column,
        Constraint,
        Create,
        Cross,
        Current,
        Declare,
        Default,
        Delete,
        Distinct,
        Drop,
        Else,
        Except,
        Exists,
        Escape,
        Fetch,
        For,
        Foreign,
        From,
        Full,
        First,
        False,
        Grant,
        Group,
        Having,
        In,
        Insert,
        Into,
        Is,
        Join,
        Left,
        Like,
        Not,
        Null,
        Of,
        On,
        Or,
        Order,
        Offset,
        Primary,
        References,
        Revoke,
        Right,
        Row,
        Select,
        Set,
        Symmetric,
        Table,
        Then,
        To,
        Trigger,
        True,
        Union,
        Unique,
        Update,
        Using,
        Values,
        When,
        Where,
        With
    }
}

impl Keyword {}

#[derive(serde::Serialize, serde::Deserialize)]
struct Comparison {
    column_name: String,
    operator: TokenT,
    number: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Predicate {
    comparisons: Vec<Comparison>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Statement {
    statement_t: StatementT,
    columns: Vec<String>,
    table_name: String,
    predicate: Predicate,
}

impl Statement {
    fn next_eq(index: &mut usize, statement: &[u8], target: &[u8]) -> bool {
        let mut is_eq = true;
        let mut i = 0;
        let mut new_index = *index;
        while i < target.len() && is_eq {
            if statement.get(new_index).unwrap() != target.get(i).unwrap() {
                is_eq = false;
            }
            i += 1;
            new_index += 1;
        }
        if is_eq {
            *index = new_index;
        }
        return is_eq;
    }

    fn read_ident(start: usize, statement: &[u8], word: &mut String) {
        let mut is_alnum = true;
        let mut i = start;
        while i < statement.len() && is_alnum {
            let cur = statement.get(i).unwrap();
            if cur.is_ascii_alphanumeric() {
                word.push(*cur as char);
            } else {
                is_alnum = false;
            }
            i += 1;
        }
    }

    fn try_read_ident(index: &mut usize, cur: &u8, statement: &[u8], word: &mut String) -> bool {
        let mut is_word = false;
        if cur.is_ascii_alphabetic() {
            is_word = true;
            Statement::read_ident(*index, statement, word);
        }
        return is_word;
    }

    fn read_num(start: usize, statement: &[u8], num: &mut String) {
        let mut is_digit = true;
        let mut i = start;
        let (mut dot_count, mut has_two_dots) = (0, false);
        while i < statement.len() && is_digit && !has_two_dots {
            let cur = statement.get(i).unwrap();
            if cur.is_ascii_digit() {
                num.push(*cur as char);
            } else if cur == &b'.' {
                dot_count += 1;
                if dot_count == 2 {
                    has_two_dots = true;
                } else {
                    num.push('.');
                }
            } else {
                is_digit = false;
            }
            i += 1;
        }
    }

    fn try_read_num(index: &mut usize, cur: &u8, statement: &[u8], num: &mut String) -> bool {
        let mut is_num = false;
        if cur.is_ascii_digit() {
            is_num = true;
            Statement::read_num(*index, statement, num);
        }
        return is_num;
    }

    fn select_token(index: &mut usize, statement: &[u8]) -> Token {
        let cur = statement.get(*index).unwrap();
        let mut val = String::new();
        let token_t = if cur.is_ascii_whitespace() {
            TokenT::Whitespace
        } else if cur == &b'=' {
            TokenT::Eq
        } else if cur == &b'>' {
            if Statement::next_eq(index, statement, b"=") {
                TokenT::GreaterEq
            } else {
                TokenT::Greater
            }
        } else if cur == &b'<' {
            if Statement::next_eq(index, statement, b">") {
                TokenT::NotEq
            } else if Statement::next_eq(index, statement, b"=") {
                TokenT::LessEq
            } else {
                TokenT::Less
            }
        } else if cur == &b',' {
            TokenT::Comma
        } else if cur == &b'.' {
            TokenT::Dot
        } else if Statement::try_read_num(index, cur, statement, &mut val) {
            TokenT::Num
        } else if Statement::try_read_ident(index, cur, statement, &mut val) {
            TokenT::Ident
        } else {
            TokenT::Error
        };
        *index += 1;
        return Token { token_t, val };
    }

    fn tokenize(statement_str: &String) -> Vec<Token> {
        let statement_bytes = statement_str.as_bytes();
        let mut tokens: Vec<Token> = vec![];
        let mut i = 0;
        while i < statement_str.len() {
            let mut token;
            loop {
                token = Statement::select_token(&mut i, statement_bytes);
                if token.token_t != TokenT::Whitespace {
                    break;
                }
            }
            tokens.push(token);
        }
        return tokens;
    }

    fn init_type(&mut self, token_index: &mut usize, tokens: &Vec<Token>) -> Result<(), String> {
        let mut result = Ok(());
        if *token_index < tokens.len() {
            let first_token = tokens.get(*token_index).unwrap();
            Statement::expect_token_t(&first_token.token_t, vec![TokenT::Ident])?;
            let val = &first_token.val;
            self.statement_t =
                if val == "insert" && tokens.get(*token_index + 1).unwrap().val == "into" {
                    StatementT::Insert
                } else if val == "select" {
                    StatementT::Select
                } else if val == "update" {
                    StatementT::Update
                } else {
                    result = Err(format!(
                        "{}: did not expect {} as statement type string",
                        function!(),
                        val
                    ));
                    StatementT::Error
                };
            *token_index += 1;
        }
        return result;
    }

    fn parse_insert(
        &mut self,
        token_index: &mut usize,
        tokens: &Vec<Token>,
        keyword_strings: &Vec<String>,
    ) -> Result<(), String> {
        let mut result = Ok(());
        return result;
    }

    fn parse_select_columns(
        &mut self,
        token_index: &mut usize,
        tokens: &Vec<Token>,
        keyword_strings: &Vec<String>,
    ) -> Result<(), String> {
        let mut result = Ok(());
        let mut must_be_ident = true;
        let mut reached_keyword = false;
        while *token_index < tokens.len() && !reached_keyword {
            let token = tokens.get(*token_index).unwrap();
            let token_t = &token.token_t;
            if must_be_ident {
                Statement::expect_token_t(token_t, vec![TokenT::Ident])?;
                if keyword_strings.contains(&token.val) {
                    reached_keyword = true;
                } else {
                    self.columns.push(token.val.to_owned());
                }
            } else {
                Statement::expect_token_t(token_t, vec![TokenT::Comma])?;
            }
            must_be_ident = !must_be_ident;
            *token_index += 1;
        }
        return result;
    }

    fn expect_val(token: &Token, expecting: &String) -> Result<(), String> {
        let mut result = Ok(());
        if &token.val != expecting {
            result = Err(format!(
                "{}: expected {} as token value, found: {}",
                function!(),
                expecting,
                &token.val
            ));
        }
        return result;
    }

    fn expect_keyword(token: &Token, keyword_strings: &Vec<String>) -> Result<(), String> {
        let mut result = Ok(());
        if !keyword_strings.contains(&token.val) {
            result = Err(format!(
                "{}: expected keyword, found: {}",
                function!(),
                token.val
            ));
        }
        return result;
    }

    fn parse_word(
        token_index: &mut usize,
        tokens: &Vec<Token>,
        word: &String,
    ) -> Result<(), String> {
        let mut result = Ok(());
        if *token_index < tokens.len() {
            let token = tokens.get(*token_index).unwrap();
            Statement::expect_token_t(&token.token_t, vec![TokenT::Ident])?;
            Statement::expect_val(token, word)?;
            *token_index += 1;
        }
        return result;
    }

    fn parse_table_name(
        &mut self,
        token_index: &mut usize,
        tokens: &Vec<Token>,
        keyword_strings: &Vec<String>,
    ) -> Result<(), String> {
        let result = Ok(());
        if *token_index < tokens.len() {
            let token = tokens.get(*token_index).unwrap();
            Statement::expect_token_t(&token.token_t, vec![TokenT::Ident])?;
            self.table_name = token.val.to_owned();
            *token_index += 1;
        }
        if *token_index < tokens.len() {
            Statement::expect_keyword(tokens.get(*token_index).unwrap(), keyword_strings)?;
        }
        return result;
    }

    fn expect_token_t(token_t: &TokenT, targets: Vec<TokenT>) -> Result<(), String> {
        let mut result = Ok(());
        if !targets.contains(&token_t) {
            result = Err(format!(
                "{}: expected one of {}, found: {}",
                function!(),
                serde_json::to_string_pretty(&targets).unwrap(),
                serde_json::to_string(&token_t).unwrap()
            ));
        }
        return result;
    }

    fn parse_comparison(
        &mut self,
        token_index: &mut usize,
        tokens: &Vec<Token>,
    ) -> Result<(), String> {
        let result = Ok(());
        let mut cur_token = &Token {
            token_t: TokenT::Error,
            val: String::new(),
        };
        let mut operator = TokenT::Error;
        let mut column_name = String::new();
        if *token_index < tokens.len() {
            cur_token = tokens.get(*token_index).unwrap();
            Statement::expect_token_t(&cur_token.token_t, vec![TokenT::Ident])?;
            column_name = cur_token.val.to_owned();
            *token_index += 1;
        }
        if *token_index < tokens.len() {
            cur_token = tokens.get(*token_index).unwrap();
            Statement::expect_token_t(
                &cur_token.token_t,
                vec![
                    TokenT::Greater,
                    TokenT::GreaterEq,
                    TokenT::Less,
                    TokenT::LessEq,
                    TokenT::Eq,
                ],
            )?;
            operator = cur_token.token_t.to_owned();
            *token_index += 1;
        }
        if *token_index < tokens.len() {
            cur_token = tokens.get(*token_index).unwrap();
            Statement::expect_token_t(&cur_token.token_t, vec![TokenT::Num])?;
            let number = cur_token.val.to_owned();
            self.predicate.comparisons.push(Comparison {
                column_name,
                operator,
                number,
            });
            *token_index += 1;
        }
        return result;
    }

    fn parse_predicate(
        &mut self,
        token_index: &mut usize,
        tokens: &Vec<Token>,
    ) -> Result<(), String> {
        let mut result = Ok(());
        self.parse_comparison(token_index, tokens)?;
        if *token_index < tokens.len() {}
        return result;
    }

    fn parse_select(
        &mut self,
        token_index: &mut usize,
        tokens: &Vec<Token>,
        keyword_strings: &Vec<String>,
    ) -> Result<(), String> {
        let result = Ok(());
        self.parse_select_columns(token_index, tokens, keyword_strings)?;
        Statement::parse_word(token_index, tokens, &"from".to_string())?;
        self.parse_table_name(token_index, tokens, keyword_strings)?;
        Statement::parse_word(token_index, tokens, &"where".to_string())?;
        self.parse_predicate(token_index, tokens)?;
        return result;
    }

    fn parse_update(
        &mut self,
        token_index: &mut usize,
        tokens: &Vec<Token>,
        keyword_strings: &Vec<String>,
    ) -> Result<(), String> {
        let mut result = Ok(());
        return result;
    }

    fn init_keyword_strings(strings: &mut Vec<String>) {
        for variant in Keyword::iter() {
            strings.push(serde_json::to_string(&variant).unwrap());
        }
    }

    fn parse(statement_str: &String) -> Result<Statement, String> {
        let tokens: Vec<Token> = Statement::tokenize(&statement_str.to_ascii_lowercase());
        let mut statement = Statement {
            statement_t: StatementT::Select,
            columns: Vec::new(),
            table_name: String::new(),
            predicate: Predicate {
                comparisons: Vec::new(),
            },
        };
        let mut keyword_strings: Vec<String> = Vec::new();
        Statement::init_keyword_strings(&mut keyword_strings);
        let mut token_index = 0;
        statement.init_type(&mut token_index, &tokens)?;
        if statement.statement_t == StatementT::Insert {
            statement.parse_insert(&mut token_index, &tokens, &keyword_strings)?;
        } else if statement.statement_t == StatementT::Select {
            statement.parse_select(&mut token_index, &tokens, &keyword_strings)?;
        } else if statement.statement_t == StatementT::Update {
            statement.parse_update(&mut token_index, &tokens, &keyword_strings)?;
        }
        return Ok(statement);
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Row {}

#[derive(serde::Serialize, serde::Deserialize)]
struct Database {
    rows: Vec<Row>,
}

impl Database {
    fn init(&mut self) {}

    fn run_statement(&mut self, statement_str: &String) -> Result<String, String> {
        let mut result = Ok(String::new());
        let parse_result = Statement::parse(statement_str);
        if parse_result.is_ok() {
            let mut resp = String::new();
        } else {
            result = Err(parse_result.err().unwrap());
        }
        return result;
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Server {
    conf: Config,
    database: Database,
}

impl Server {
    fn init(&mut self) {
        self.conf.init();
        self.database.init();
    }

    fn apply(&mut self, statement_str: &String) -> Result<String, String> {
        let mut result = Ok(String::new());
        // self.consensus.commit(statement_str);
        // do not call run_statement immediately, read from log first
        let statement_result = self.database.run_statement(statement_str);
        if statement_result.is_ok() {
            let resp = statement_result.unwrap();
            result = Ok(resp);
        } else {
            result = Err(statement_result.err().unwrap());
        }
        return result;
    }

    fn handle_connection(&mut self, stream: &mut std::net::TcpStream) {
        let mut statement_str: String = String::new();
        stream.read_to_string(&mut statement_str).unwrap();
        let apply_result = self.apply(&statement_str);
        if apply_result.is_ok() {
            stream.write_all(apply_result.unwrap().as_bytes()).unwrap();
        } else {
            stream
                .write_all(apply_result.err().unwrap().as_bytes())
                .unwrap();
        }
    }

    fn listen(&mut self) {
        let listener = std::net::TcpListener::bind("0.0.0.0:6789")
            .expect(&format!("{}: bind failed", function!()));
        for stream in listener.incoming() {
            self.handle_connection(&mut stream.unwrap());
        }
    }
}

fn main() {
    env_logger::init();
    let mut server = Server {
        conf: Config {
            pool_id: 0,
            peers: Vec::new(),
        },
        database: Database { rows: Vec::new() },
    };
    server.init();
    server.listen();
}
