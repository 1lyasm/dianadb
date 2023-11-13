#[macro_use]
extern crate log;

#[macro_use]
mod util;

extern crate nix;

use std::{
    fmt::format,
    io::{Read, Write},
};

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

fn get_res<T>(iterable: &[T], index: usize) -> Result<&T, Box<dyn std::error::Error>> {
    let result;
    let opt = iterable.get(index);
    if opt.is_some() {
        result = Ok(opt.unwrap());
    } else {
        result = Err("index out of bounds".into());
    }
    return result;
}

fn get_res_mut<T>(iterable: &mut [T], index: usize) -> Result<&mut T, Box<dyn std::error::Error>> {
    let result;
    let opt = iterable.get_mut(index);
    if opt.is_some() {
        result = Ok(opt.unwrap());
    } else {
        result = Err("index out of bounds".into());
    }
    return result;
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ServerConfig {
    addr: String,
    pool_id: usize,
    peers: Vec<String>,
    global_id: usize,
    me: String,
}

impl ServerConfig {
    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut res = Ok(());
        let peer_count = self.peers.len();
        if peer_count < 1 {
            res = Err(format!("{}: peer addresses are missing", crate::function!()).into());
        }
        if peer_count < 2 {
            res = Err(format!("{}: single replica not allowed", crate::function!()).into());
        }
        if peer_count % 2 == 0 {
            res = Err(format!("{}: peer count must be odd", crate::function!()).into());
        }
        return res;
    }

    fn extract_usize(
        words: &Vec<String>,
        index: usize,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let word = get_res(words, index)?;
        return Ok(word.parse::<usize>()?);
    }

    fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        debug!(
            "{}: binding to {}",
            crate::function!(),
            self.addr.to_string()
        );
        let (mut stream, _) = std::net::TcpListener::bind(self.addr.to_string())?.accept()?;
        let mut payload = String::new();
        stream.read_to_string(&mut payload)?;
        debug!("{}: payload: {}", crate::function!(), payload);
        let splitted: Vec<String> = payload.split_whitespace().map(str::to_string).collect();
        debug!(
            "{}: splitted: {}",
            crate::function!(),
            serde_json::to_string(&splitted)?
        );
        self.pool_id = ServerConfig::extract_usize(&splitted, 0)?;
        trace!(
            "{}: extracted pool_id: {}",
            crate::function!(),
            self.pool_id
        );
        self.global_id = ServerConfig::extract_usize(&splitted, 1)?;
        trace!(
            "{}: extracted global_id: {}",
            crate::function!(),
            self.global_id
        );
        self.peers = splitted[2..].to_vec();
        trace!(
            "{}: extracted peers: {}",
            crate::function!(),
            serde_json::to_string(&self.peers)?
        );
        self.me = format!("S{}", self.global_id.to_string());
        info!(
            "{}: {}: \nself: {}",
            self.me,
            crate::function!(),
            serde_json::to_string_pretty(&self)?
        );
        self.validate()?;
        return Ok(());
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Clone)]
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
    LParen,
    RParen,
    Error,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq)]
struct Token {
    token_t: TokenT,
    val: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq)]
enum StatementT {
    Insert,
    Select,
    Update,
    Create,
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

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct Comparison {
    column_name: String,
    operator: TokenT,
    number: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct Predicate {
    comparisons: Vec<Comparison>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Tokens {
    token_list: Vec<Token>,
    stream: Vec<u8>,
    me: String,
}

impl Tokens {
    fn eq(&self, other: &Tokens) -> Result<bool, Box<dyn std::error::Error>> {
        let mut is_eq = true;
        if self.token_list.len() != other.token_list.len() {
            is_eq = false;
        }
        let mut i = 0;
        while i < self.token_list.len() && is_eq {
            if get_res(&self.token_list, i)? != get_res(&other.token_list, i)? {
                is_eq = false;
            }
            i += 1;
        }
        return Ok(is_eq);
    }

    fn expect_val(
        &self,
        token: &Token,
        expecting: &String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        if &token.val != expecting {
            result = Err(format!(
                "{}: {}: expected {} as token value, found: {}",
                self.me,
                crate::function!(),
                expecting,
                &token.val
            )
            .into());
        }
        return result;
    }

    fn expect_keyword(
        &self,
        token: &Token,
        keyword_strings: &Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        if !keyword_strings.contains(&token.val) {
            result = Err(format!(
                "{}: {}: expected keyword, found: {}",
                self.me,
                crate::function!(),
                token.val
            )
            .into());
        }
        return result;
    }

    fn expect_not_keyword(
        &self,
        token: &Token,
        keyword_strings: &Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expect_keyword_res = self.expect_keyword(token, keyword_strings);
        let mut res = Ok(());
        if expect_keyword_res.is_ok() {
            res = Err(format!(
                "{}: {}: did not expect keyword, found: {}",
                self.me,
                crate::function!(),
                token.val
            )
            .into());
        }
        return res;
    }

    fn expect_token_t(
        &self,
        token_t: &TokenT,
        targets: Vec<TokenT>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        if !targets.contains(&token_t) {
            result = Err(format!(
                "{}: {}: expected one of {}, found: {}",
                self.me,
                crate::function!(),
                serde_json::to_string_pretty(&targets)?,
                serde_json::to_string(&token_t)?
            )
            .into());
        }
        return result;
    }

    fn next_eq(
        &self,
        index: &mut usize,
        target: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut is_eq = true;
        let mut i = 0;
        let mut new_index = *index;
        while i < target.len() && is_eq {
            if self.stream[new_index as usize] != target[i as usize] {
                is_eq = false;
            }
            i += 1;
            new_index += 1;
        }
        if is_eq {
            *index = new_index;
        }
        return Ok(is_eq);
    }

    fn read_ident(
        &self,
        index: &mut usize,
        word: &mut String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!(
            "{}: {}: starting index: {}",
            self.me,
            crate::function!(),
            *index
        );
        let mut is_alnum = true;
        while *index < self.stream.len() && is_alnum {
            let cur = get_res(&self.stream, *index)?;
            trace!("{}: {}: cur: {}", self.me, crate::function!(), *cur as char);
            if cur.is_ascii_alphanumeric() || cur == &('_' as u8) {
                word.push(*cur as char);
                *index += 1;
            } else {
                is_alnum = false;
            }
        }
        debug!("{}: {}: word: {}", self.me, crate::function!(), word);
        return Ok(());
    }

    fn try_read_ident(
        &self,
        index: &mut usize,
        cur: &u8,
        word: &mut String,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        debug!("{}: {}: called", self.me, crate::function!());
        let mut is_word = false;
        if cur.is_ascii_alphabetic() {
            is_word = true;
            self.read_ident(index, word)?;
        }
        return Ok(is_word);
    }

    fn read_num(
        &self,
        index: &mut usize,
        num: &mut String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!(
            "{}: {}: starting index: {}",
            self.me,
            crate::function!(),
            *index
        );
        let mut is_digit = true;
        let (mut dot_count, mut has_two_dots) = (0, false);
        while *index < self.stream.len() && is_digit && !has_two_dots {
            let cur = get_res(&self.stream, *index)?;
            if cur.is_ascii_digit() {
                num.push(*cur as char);
                *index += 1;
            } else if cur == &b'.' {
                dot_count += 1;
                if dot_count == 2 {
                    has_two_dots = true;
                } else {
                    num.push('.');
                    *index += 1;
                }
            } else {
                is_digit = false;
            }
        }
        debug!("{}: {}: num: {}", self.me, crate::function!(), num);
        return Ok(());
    }

    fn try_read_num(
        &self,
        index: &mut usize,
        cur: &u8,
        num: &mut String,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut is_num = false;
        if cur.is_ascii_digit() {
            is_num = true;
            self.read_num(index, num)?;
        }
        return Ok(is_num);
    }

    fn select_token(&self, index: &mut usize) -> Result<Token, Box<dyn std::error::Error>> {
        debug!(
            "{}: {}: starting index: {}",
            self.me,
            crate::function!(),
            *index
        );
        let mut token_t = TokenT::Error;
        let mut val = String::new();
        if *index < self.stream.len() {
            let cur = get_res(&self.stream, *index)?;
            debug!("{}: {}: cur: {}", self.me, crate::function!(), *cur as char);
            val = String::new();
            token_t = if cur.is_ascii_whitespace() {
                TokenT::Whitespace
            } else if cur == &b'=' {
                TokenT::Eq
            } else if cur == &b'>' {
                if self.next_eq(index, b"=")? {
                    TokenT::GreaterEq
                } else {
                    TokenT::Greater
                }
            } else if cur == &b'<' {
                if self.next_eq(index, b">")? {
                    TokenT::NotEq
                } else if self.next_eq(index, b"=")? {
                    TokenT::LessEq
                } else {
                    TokenT::Less
                }
            } else if cur == &b',' {
                debug!("{}: {}: selecting comma", self.me, crate::function!());
                TokenT::Comma
            } else if cur == &b'.' {
                TokenT::Dot
            } else if self.try_read_num(index, cur, &mut val)? {
                *index -= 1;
                TokenT::Num
            } else if self.try_read_ident(index, cur, &mut val)? {
                *index -= 1;
                TokenT::Ident
            } else {
                TokenT::Error
            };
            *index += 1;
        }
        return Ok(Token { token_t, val });
    }

    fn token_left(&self, index: usize) -> Result<bool, Box<dyn std::error::Error>> {
        let mut res = Ok(false);
        if index < self.token_list.len() {
            res = Ok(true);
        }
        return res;
    }

    fn tokenize(statement_str: &String, me: &String) -> Result<Tokens, Box<dyn std::error::Error>> {
        debug!("{}: {}: called", me, crate::function!());
        let mut tokens = Tokens {
            token_list: Vec::new(),
            stream: statement_str.as_bytes().to_vec(),
            me: me.to_owned(),
        };
        let mut i = 0;
        while i < tokens.stream.len() {
            let mut token;
            loop {
                token = tokens.select_token(&mut i)?;
                if token.token_t != TokenT::Whitespace {
                    break;
                }
            }
            if token.token_t != TokenT::Error {
                tokens.token_list.push(token);
            }
        }
        debug!(
            "{}: {}: tokens: {}",
            me,
            crate::function!(),
            serde_json::to_string_pretty(&tokens)?
        );
        return Ok(tokens);
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
enum SqlT {
    Integer,
    Varchar(usize),
    Char,
    Date,
    Error,
}

impl SqlT {
    fn from_str(
        s: &String,
        char_cnt: usize,
        me: &String,
    ) -> Result<SqlT, Box<dyn std::error::Error>> {
        let res = if s == &"integer".to_string() {
            Ok(SqlT::Integer)
        } else if s == &"varchar".to_string() {
            Ok(SqlT::Varchar(char_cnt))
        } else if s == &"char".to_string() {
            Ok(SqlT::Char)
        } else if s == &"date".to_string() {
            Ok(SqlT::Date)
        } else {
            Err(format!(
                "{}: {}: can not convert {} to SqlT",
                me,
                crate::function!(),
                s
            )
            .into())
        };
        return res;
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
enum ColumnConstraint {
    NotNull,
    PrimaryKey,
    Error,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ColumnInfo {
    name: String,
    data_t: SqlT,
    constraints: Vec<ColumnConstraint>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Schema {
    column_info_list: Vec<ColumnInfo>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Statement {
    me: String,
    tokens: Tokens,
    keywords: Vec<String>,

    statement_t: StatementT,
    columns: Vec<String>,
    table_name: String,
    predicate: Predicate,
    schema: Schema,
}

impl Statement {
    fn parse_type(&mut self, token_index: &mut usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        if *token_index < self.tokens.token_list.len() {
            let first_token = get_res(&self.tokens.token_list, *token_index)?;
            self.tokens
                .expect_token_t(&first_token.token_t, vec![TokenT::Ident])?;
            let val = &first_token.val;
            self.statement_t = if val == "insert"
                && get_res(&self.tokens.token_list, *token_index + 1)?.val == "into"
            {
                StatementT::Insert
            } else if val == "select" {
                StatementT::Select
            } else if val == "update" {
                StatementT::Update
            } else {
                result = Err(format!(
                    "{}: {}: did not expect {} as statement type string",
                    self.me,
                    crate::function!(),
                    val
                )
                .into());
                StatementT::Error
            };
            *token_index += 1;
        }
        return result;
    }

    fn parse_insert(&mut self, token_index: &mut usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        return result;
    }

    fn parse_select_columns(
        &mut self,
        token_index: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("{}: {}: called", self.me, crate::function!());
        let mut result = Ok(());
        let mut must_be_ident = true;
        let mut reached_keyword = false;
        let start_index = *token_index;
        while *token_index < self.tokens.token_list.len() && !reached_keyword {
            let token = get_res(&self.tokens.token_list, *token_index)?;
            let token_t = &token.token_t;
            debug!(
                "{}: {}: token: {}",
                self.me,
                crate::function!(),
                serde_json::to_string(&token)?
            );
            trace!(
                "{}: {}: self.keywords: {}",
                self.me,
                crate::function!(),
                serde_json::to_string(&self.keywords)?
            );
            if token.token_t == TokenT::Ident && self.keywords.contains(&token.val) {
                debug!("{}: {}: reached_keyword", self.me, crate::function!());
                reached_keyword = true;
            }
            if !reached_keyword {
                if must_be_ident {
                    self.tokens.expect_token_t(token_t, vec![TokenT::Ident])?;
                    self.columns.push(token.val.to_owned());
                } else {
                    self.tokens.expect_token_t(token_t, vec![TokenT::Comma])?;
                }
                must_be_ident = !must_be_ident;
                *token_index += 1;
            }
        }
        debug!(
            "{}: {}: columns: {}",
            self.me,
            crate::function!(),
            self.columns.join(" ")
        );
        debug!("{}: {}: returning", self.me, crate::function!());
        if *token_index == start_index {
            result =
                Err(format!("{}: {}: column names missing", self.me, crate::function!()).into());
        }
        return result;
    }

    fn skip_word(
        &self,
        token_index: &mut usize,
        word: &String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        if *token_index < self.tokens.token_list.len() {
            let token = get_res(&self.tokens.token_list, *token_index)?;
            self.tokens
                .expect_token_t(&token.token_t, vec![TokenT::Ident])?;
            self.tokens.expect_val(token, word)?;
            *token_index += 1;
        }
        return result;
    }

    fn parse_table_name(
        &mut self,
        token_index: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        let start_index = *token_index;
        if *token_index < self.tokens.token_list.len() {
            let token = get_res(&self.tokens.token_list, *token_index)?;
            self.tokens
                .expect_token_t(&token.token_t, vec![TokenT::Ident])?;
            self.table_name = token.val.to_owned();
            *token_index += 1;
        }
        if *token_index == start_index {
            result =
                Err(format!("{}: {}: table name not found", self.me, crate::function!()).into());
        } else if *token_index < self.tokens.token_list.len() {
            self.tokens.expect_keyword(
                get_res(&self.tokens.token_list, *token_index)?,
                &self.keywords,
            )?;
        }
        return result;
    }

    fn parse_comparison(
        &mut self,
        token_index: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = Ok(());
        let mut cur_token;
        let mut operator = TokenT::Error;
        let mut column_name = String::new();
        if *token_index < self.tokens.token_list.len() {
            cur_token = get_res(&self.tokens.token_list, *token_index)?;
            self.tokens
                .expect_token_t(&cur_token.token_t, vec![TokenT::Ident])?;
            column_name = cur_token.val.to_owned();
            *token_index += 1;
        }
        if *token_index < self.tokens.token_list.len() {
            cur_token = get_res(&self.tokens.token_list, *token_index)?;
            self.tokens.expect_token_t(
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
        if *token_index < self.tokens.token_list.len() {
            cur_token = get_res(&self.tokens.token_list, *token_index)?;
            self.tokens
                .expect_token_t(&cur_token.token_t, vec![TokenT::Num])?;
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("{}: {}: called", self.me, crate::function!());
        let mut result = Ok(());
        let start_index = *token_index;
        // TODO do this for multiple comparisons
        self.parse_comparison(token_index)?;
        if *token_index == start_index {
            debug!(
                "{}: {}: token_index == start_index",
                self.me,
                crate::function!()
            );
            result = Err(format!(
                "{}: {}: empty where clause not allowed",
                self.me,
                crate::function!()
            )
            .into());
        }
        return result;
    }

    fn parse_select(&mut self, token_index: &mut usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        self.parse_select_columns(token_index)?;
        self.skip_word(token_index, &"from".to_string())?;
        self.parse_table_name(token_index)?;
        let before_where_index = *token_index;
        self.skip_word(token_index, &"where".to_string())?;
        let has_where = *token_index != before_where_index;
        if has_where {
            self.parse_predicate(token_index)?;
        }
        return result;
    }

    fn parse_update(&mut self, token_index: &mut usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        return result;
    }

    fn init_keyword_strings(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        for variant in Keyword::iter() {
            let variant_as_str = serde_json::to_string(&variant)?;
            self.keywords.push(
                variant_as_str[1..variant_as_str.len() - 1]
                    .to_string()
                    .to_lowercase(),
            );
        }
        return Ok(());
    }

    fn expect_end(&self, index: usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut res = Ok(());
        if index != self.tokens.token_list.len() {
            res = Err(format!(
                "{}: {}: expected token index to be equal to length of tokens",
                self.me,
                crate::function!()
            )
            .into());
        }
        return res;
    }

    fn parse_column_info(
        &mut self,
        token_idx: &mut usize,
        col_idx: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut res = Ok(());
        let col_info = get_res_mut(&mut self.schema.column_info_list, col_idx)?;

        if self.tokens.token_left(*token_idx)? {
            let col_name_token = get_res(&self.tokens.token_list, *token_idx)?;
            self.tokens
                .expect_token_t(&col_name_token.token_t, vec![TokenT::Ident])?;
            self.tokens
                .expect_not_keyword(col_name_token, &self.keywords)?;
            col_info.name = col_name_token.val.to_string();
            *token_idx += 1;
        }

        if self.tokens.token_left(*token_idx)? {
            let col_type_tok = get_res(&self.tokens.token_list, *token_idx)?;
            self.tokens
                .expect_token_t(&col_type_tok.token_t, vec![TokenT::Ident])?;
            self.tokens
                .expect_not_keyword(col_type_tok, &self.keywords)?;
            col_info.data_t = SqlT::from_str(&col_type_tok.val, 0, &self.me)?;
            *token_idx += 1;
        }

        return res;
    }

    fn parse_create(&mut self, token_index: &mut usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut res = Ok(());
        self.skip_word(token_index, &"table".to_string())?;

        if self.tokens.token_left(*token_index)? {
            let table_name_token = get_res(&self.tokens.token_list, *token_index)?;
            self.tokens
                .expect_token_t(&table_name_token.token_t, vec![TokenT::Ident])?;
            self.tokens
                .expect_not_keyword(table_name_token, &self.keywords)?;
            self.table_name = table_name_token.val.to_owned();
            *token_index += 1;
        } else {
            res = Err(format!("{}: {}: table name missing", self.me, crate::function!()).into());
        }

        if self.tokens.token_left(*token_index)? {
            let left_paren_token = get_res(&self.tokens.token_list, *token_index)?;
            self.tokens
                .expect_token_t(&left_paren_token.token_t, vec![TokenT::LParen])?;
            *token_index += 1;
        } else {
            res = Err(format!("{}: {}: schema missing", self.me, crate::function!()).into());
        }

        if self.tokens.token_left(*token_index)? {
            // TODO do this for all columns
            let mut col_idx = 0;
            self.parse_column_info(token_index, col_idx)?;
        } else {
            res = Err(format!(
                "{}: {}: expected something after left paren",
                self.me,
                crate::function!()
            )
            .into());
        }

        return res;
    }

    fn parse(statement_str: &String, me: &String) -> Result<Statement, Box<dyn std::error::Error>> {
        let mut statement = Statement {
            me: me.to_owned(),
            tokens: Tokens::tokenize(&statement_str.to_ascii_lowercase(), me)?,
            keywords: Vec::new(),

            statement_t: StatementT::Error,
            columns: Vec::new(),
            table_name: String::new(),
            predicate: Predicate {
                comparisons: Vec::new(),
            },
            schema: Schema {
                column_info_list: vec![],
            },
        };
        statement.init_keyword_strings()?;
        let mut token_index = 0;
        statement.parse_type(&mut token_index)?;
        if statement.statement_t == StatementT::Insert {
            statement.parse_insert(&mut token_index)?;
        } else if statement.statement_t == StatementT::Select {
            statement.parse_select(&mut token_index)?;
        } else if statement.statement_t == StatementT::Update {
            statement.parse_update(&mut token_index)?;
        } else if statement.statement_t == StatementT::Create {
            statement.parse_create(&mut token_index)?;
        }
        statement.expect_end(token_index)?;
        return Ok(statement);
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Row {}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Table {
    pub rows: Vec<Row>,
}

impl Table {
    pub fn print(&self) {}
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Database {
    me: String,
}

impl Database {
    fn init(&mut self, me: &String) -> Result<(), Box<dyn std::error::Error>> {
        self.me = me.to_owned();
        return Ok(());
    }

    fn run_statement(
        &mut self,
        statement_str: &String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut result = Ok(String::new());
        let parse_res = Statement::parse(statement_str, &self.me);
        match parse_res {
            Ok(v) => {
                let resp = String::new();
            }
            Err(e) => {
                result = Err(e);
            }
        }
        return result;
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Server {
    conf: ServerConfig,
    database: Database,
}

impl Server {
    fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.conf.init()?;
        self.database.init(&self.conf.me)?;
        return Ok(());
    }

    fn apply(&mut self, statement_str: &String) -> Result<String, Box<dyn std::error::Error>> {
        let mut result = Ok(String::new());
        // TODO commit to logs
        // TODO read from logs before calling run_statement
        let statement_result = self.database.run_statement(statement_str);
        match statement_result {
            Ok(v) => {
                result = Ok(v);
            }
            Err(e) => {
                result = Err(e);
            }
        }
        return result;
    }

    fn handle_connection(
        &mut self,
        stream: &mut std::net::TcpStream,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut statement_str: String = String::new();
        stream.read_to_string(&mut statement_str)?;
        let apply_result = self.apply(&statement_str);
        match apply_result {
            Ok(v) => {
                stream.write_all(v.as_bytes())?;
            }
            Err(e) => {
                stream.write_all(e.to_string().as_bytes())?;
            }
        }
        return Ok(());
    }

    fn listen(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind(self.conf.addr.to_string())?;
        for stream in listener.incoming() {
            self.handle_connection(&mut stream?)?;
        }
        return Ok(());
    }

    pub fn run(addr: &String) -> Result<(), Box<dyn std::error::Error>> {
        env_logger::init();
        info!("{}: server started", crate::function!());
        let mut server = Server {
            conf: ServerConfig {
                addr: addr.to_string(),
                pool_id: 0,
                peers: Vec::new(),
                global_id: 0,
                me: String::new(),
            },
            database: Database { me: String::new() },
        };
        server.init()?;
        server.listen()?;
        return Ok(());
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ClientConfig {
    shard_count: usize,
    addresses: Vec<String>,
    pools: Vec<usize>,
}

impl ClientConfig {
    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        let mut is_valid = true;
        let server_count = self.addresses.len();
        let replica_count = server_count / self.shard_count;
        if server_count % self.shard_count != 0 {
            is_valid = false;
        }
        if replica_count <= 1 || replica_count % 2 == 0 {
            is_valid = false;
        }
        if !is_valid {
            result = Err(format!("{}: invalid conf", crate::function!()).into());
        }
        return result;
    }

    fn init_pools(shard_count: usize, addresses: &Vec<String>) -> Vec<usize> {
        let (mut current_pool, mut j) = (0, 0);
        let server_count = addresses.len();
        let replica_count = server_count / shard_count;
        let mut pools = Vec::new();
        for _ in 0..server_count {
            if j == replica_count {
                current_pool += 1;
                j = 0;
            }
            pools.push(current_pool);
            j += 1;
        }
        return pools;
    }

    fn merge_by_pools(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut pool_addresses = Vec::new();
        for _ in 0..self.shard_count {
            pool_addresses.push("".to_owned());
        }
        for i in 0..self.addresses.len() {
            get_res_mut(&mut pool_addresses, *get_res(&self.pools, i)?)?
                .push_str(&(get_res(&self.addresses, i)?.to_owned() + " "));
        }
        return Ok(pool_addresses);
    }

    fn send(
        &self,
        address: &String,
        pool: &usize,
        global_id: usize,
        peers: &String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool_str = pool.to_string();
        let global_id_str = global_id.to_string();
        info!(
            "{}: sending [{}, {}, {}] to {}",
            crate::function!(),
            pool_str,
            global_id_str,
            peers,
            address
        );
        let mut stream = std::net::TcpStream::connect(address)?;
        let payload = format!("{} {} {}", pool_str, global_id_str, peers);
        info!("{}: payload: {}", crate::function!(), payload);
        stream.write_all(payload.as_bytes())?;
        return Ok(());
    }

    fn send_all(&self) -> Result<(), Box<dyn std::error::Error>> {
        let pool_addresses = self.merge_by_pools()?;
        for i in 0..self.addresses.len() {
            let address = get_res(&self.addresses, i)?;
            let pool = get_res(&self.pools, i)?;
            let peers = get_res(&pool_addresses, *pool)?;
            self.send(address, pool, i, &peers)?;
        }
        return Ok(());
    }
}

pub struct Client {
    conf: ClientConfig,
}

impl Client {
    pub fn run_statement(&self, statement: &String) -> Result<Table, Box<dyn std::error::Error>> {
        return Ok(Table { rows: Vec::new() });
    }

    pub fn connect(
        shard_count: usize,
        addresses: &Vec<String>,
    ) -> Result<Client, Box<dyn std::error::Error>> {
        env_logger::init();
        info!("{}: client started", crate::function!());
        let conf = ClientConfig {
            shard_count,
            addresses: addresses.to_owned(),
            pools: ClientConfig::init_pools(shard_count, &addresses),
        };
        info!(
            "{}: conf: \n{}",
            crate::function!(),
            serde_json::to_string_pretty(&conf)?
        );
        conf.validate()?;
        conf.send_all()?;
        return Ok(Client { conf });
    }
}

#[cfg(test)]
mod tests {
    use crate::Comparison;
    use crate::Predicate;
    use crate::Statement;
    use crate::StatementT;
    use crate::Token;
    use crate::TokenT;
    use crate::Tokens;

    fn test_tokenize() -> Result<(), Box<dyn std::error::Error>> {
        let mut tokens_res;
        let mut expected;
        let mut eq_res;

        tokens_res = Tokens::tokenize(&"select name from table_1".to_string(), &"S0".to_string());
        assert!(tokens_res.is_ok() == true);
        expected = Tokens {
            token_list: vec![
                Token {
                    token_t: TokenT::Ident,
                    val: "select".to_string(),
                },
                Token {
                    token_t: TokenT::Ident,
                    val: "name".to_string(),
                },
                Token {
                    token_t: TokenT::Ident,
                    val: "from".to_string(),
                },
                Token {
                    token_t: TokenT::Ident,
                    val: "table_1".to_string(),
                },
            ],
            me: "S0".to_string(),
            stream: Vec::new(),
        };
        eq_res = tokens_res.as_ref().unwrap().eq(&expected);
        assert!(eq_res.is_ok() == true);
        assert!(eq_res.unwrap() == true);

        tokens_res = Tokens::tokenize(
            &"select column1, column2, column3\nfrom table_name\nwhere column1 > 500\n\n"
                .to_string(),
            &"S0".to_string(),
        );
        if tokens_res.is_err() {
            debug!(
                "{}: tokens_res error: {}",
                crate::function!(),
                tokens_res.as_ref().err().unwrap()
            );
        }
        assert!(tokens_res.is_ok() == true);
        expected = Tokens {
            token_list: vec![
                Token {
                    token_t: TokenT::Ident,
                    val: "select".to_string(),
                },
                Token {
                    token_t: TokenT::Ident,
                    val: "column1".to_string(),
                },
                Token {
                    token_t: TokenT::Comma,
                    val: String::new(),
                },
                Token {
                    token_t: TokenT::Ident,
                    val: "column2".to_string(),
                },
                Token {
                    token_t: TokenT::Comma,
                    val: String::new(),
                },
                Token {
                    token_t: TokenT::Ident,
                    val: "column3".to_string(),
                },
                Token {
                    token_t: TokenT::Ident,
                    val: "from".to_string(),
                },
                Token {
                    token_t: TokenT::Ident,
                    val: "table_name".to_string(),
                },
                Token {
                    token_t: TokenT::Ident,
                    val: "where".to_string(),
                },
                Token {
                    token_t: TokenT::Ident,
                    val: "column1".to_string(),
                },
                Token {
                    token_t: TokenT::Greater,
                    val: String::new(),
                },
                Token {
                    token_t: TokenT::Num,
                    val: "500".to_string(),
                },
            ],
            me: "S0".to_string(),
            stream: Vec::new(),
        };
        eq_res = tokens_res.as_ref().unwrap().eq(&expected);
        assert!(eq_res.is_ok() == true);
        assert!(eq_res.unwrap() == true);
        return Ok(());
    }

    fn test_parse() -> Result<(), Box<dyn std::error::Error>> {
        let mut query;
        let mut parse_res;
        let mut statement;

        query = "select name from table_1".to_string();
        parse_res = Statement::parse(&query, &"S0".to_string());
        assert!(parse_res.is_ok() == true);
        statement = parse_res.unwrap();
        trace!(
            "{}: statement: {}",
            crate::function!(),
            serde_json::to_string(&statement)?
        );
        assert!(statement.statement_t == StatementT::Select);
        assert!(statement.columns == vec!["name"]);
        assert!(
            statement.predicate
                == Predicate {
                    comparisons: vec![]
                }
        );

        query =
            "SELECT column_1, COLUMN_2, column_3 FROM my_table where column_1 > 500".to_string();
        parse_res = Statement::parse(&query, &"S0".to_string());
        assert!(parse_res.is_ok() == true);
        statement = parse_res.unwrap();
        trace!(
            "{}: statement: {}",
            crate::function!(),
            serde_json::to_string(&statement)?
        );
        assert!(statement.statement_t == StatementT::Select);
        assert!(
            statement.columns
                == vec![
                    "column_1".to_string(),
                    "column_2".to_string(),
                    "column_3".to_string()
                ]
        );
        assert!(statement.table_name == "my_table".to_string());
        assert!(
            statement.predicate
                == Predicate {
                    comparisons: vec![Comparison {
                        column_name: "column_1".to_string(),
                        operator: TokenT::Greater,
                        number: "500".to_string()
                    }]
                }
        );

        query = "selet name from table_name".to_string();
        parse_res = Statement::parse(&query, &"S0".to_string());
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_res error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name from table_1 something".to_string();
        parse_res = Statement::parse(&query, &"S0".to_string());
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name from table_1 where name = 400 something".to_string();
        parse_res = Statement::parse(&query, &"S0".to_string());
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name from table_1 where name = 400 1".to_string();
        parse_res = Statement::parse(&query, &"S0".to_string());
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select from table_1 where name = 400".to_string();
        parse_res = Statement::parse(&query, &"S0".to_string());
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name from where name = 400".to_string();
        parse_res = Statement::parse(&query, &"S0".to_string());
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name from table_name where".to_string();
        parse_res = Statement::parse(&query, &"S0".to_string());
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name form table_name".to_string();
        parse_res = Statement::parse(&query, &"S0".to_string());
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        return Ok(());
    }

    fn test_tokens() -> Result<(), Box<dyn std::error::Error>> {
        test_tokenize()?;
        return Ok(());
    }

    fn test_statement() -> Result<(), Box<dyn std::error::Error>> {
        test_parse()?;
        return Ok(());
    }

    #[test]
    fn test() {
        env_logger::init();
        test_tokens().expect("test_tokens failed");
        test_statement().expect("test_statement failed");
    }
}
