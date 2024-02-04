use std::io::BufRead;
use std::io::Write;

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
        const COUNT_MEMBERS: usize = $crate::count!($($member)*);
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
    tok_t: TokenT,
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
    tok_list: Vec<Token>,
    stream: Vec<u8>,
}

impl Tokens {
    fn expect_val(
        &self,
        tok: &Token,
        expecting: &String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        if &tok.val != expecting {
            result = Err(format!(
                "{}: expected '{}' as tok value, found: '{}'",
                crate::function!(),
                expecting,
                &tok.val
            )
            .into());
        }
        return result;
    }

    fn expect_keyword(
        &self,
        tok: &Token,
        keyword_strings: &Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        if !keyword_strings.contains(&tok.val) {
            result = Err(format!(
                "{}: expected keyword, found: {}",
                crate::function!(),
                tok.val
            )
            .into());
        }
        return result;
    }

    fn expect_not_keyword(
        &self,
        tok: &Token,
        keyword_strings: &Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expect_keyword_res = self.expect_keyword(tok, keyword_strings);
        let mut res = Ok(());
        if expect_keyword_res.is_ok() {
            res = Err(format!(
                "{}: did not expect keyword, found: '{}'",
                crate::function!(),
                tok.val
            )
            .into());
        }
        return res;
    }

    fn expect_tok_t(
        &self,
        tok_t: &TokenT,
        targets: Vec<TokenT>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        if !targets.contains(&tok_t) {
            result = Err(format!(
                "{}: expected one of {}, found: {}",
                crate::function!(),
                serde_json::to_string_pretty(&targets)?,
                serde_json::to_string(&tok_t)?
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
            "{}: starting index: {}",
            crate::function!(),
            *index
        );
        let mut is_alnum = true;
        while *index < self.stream.len() && is_alnum {
            let cur = get_res(&self.stream, *index)?;
            trace!("{}: cur: {}", crate::function!(), *cur as char);
            if cur.is_ascii_alphanumeric() || cur == &('_' as u8) {
                word.push(*cur as char);
                *index += 1;
            } else {
                is_alnum = false;
            }
        }
        debug!("{}: word: {}", crate::function!(), word);
        return Ok(());
    }

    fn try_read_ident(
        &self,
        index: &mut usize,
        cur: &u8,
        word: &mut String,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        debug!("{}: called", crate::function!());
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
            "{}: starting index: {}",
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
        debug!("{}: num: {}", crate::function!(), num);
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

    fn select_tok(&self, index: &mut usize) -> Result<Token, Box<dyn std::error::Error>> {
        debug!(
            "{}: starting index: {}",
            crate::function!(),
            *index
        );
        let mut tok_t = TokenT::Error;
        let mut val = String::new();
        if *index < self.stream.len() {
            let cur = get_res(&self.stream, *index)?;
            debug!("{}: cur: {}", crate::function!(), *cur as char);
            val = String::new();
            tok_t = if cur.is_ascii_whitespace() {
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
                debug!("{}: selecting comma", crate::function!());
                TokenT::Comma
            } else if cur == &b'.' {
                TokenT::Dot
            } else if cur == &b'(' {
                TokenT::LParen
            } else if cur == &b')' {
                TokenT::RParen
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
        return Ok(Token { tok_t, val });
    }

    fn tok_left(&self, index: usize) -> Result<bool, Box<dyn std::error::Error>> {
        let mut res = Ok(false);
        if index < self.tok_list.len() {
            res = Ok(true);
        }
        return res;
    }

    fn tokize(statement_str: &String) -> Result<Tokens, Box<dyn std::error::Error>> {
        debug!("{}: called", crate::function!());
        let mut toks = Tokens {
            tok_list: Vec::new(),
            stream: statement_str.as_bytes().to_vec(),
        };
        let mut i = 0;
        while i < toks.stream.len() {
            let mut tok;
            loop {
                tok = toks.select_tok(&mut i)?;
                if tok.tok_t != TokenT::Whitespace {
                    break;
                }
            }
            if tok.tok_t != TokenT::Error {
                toks.tok_list.push(tok);
            }
        }
        debug!(
            "{}: toks: {}",
            crate::function!(),
            serde_json::to_string_pretty(&toks)?
        );
        println!("{}", serde_json::to_string_pretty(&toks)?);
        return Ok(toks);
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
enum SqlT {
    Int,
    Varchar(usize),
    Char,
    Date,
    Error,
}

impl SqlT {
    fn from_str(
        s: &String,
        char_cnt: usize,
    ) -> Result<SqlT, Box<dyn std::error::Error>> {
        let res = if s == &"int".to_string() {
            Ok(SqlT::Int)
        } else if s == &"varchar".to_string() {
            Ok(SqlT::Varchar(char_cnt))
        } else if s == &"char".to_string() {
            Ok(SqlT::Char)
        } else if s == &"date".to_string() {
            Ok(SqlT::Date)
        } else {
            Err(format!(
                "{}: '{}' is not a SQL type",
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
    toks: Tokens,
    keywords: Vec<String>,

    statement_t: StatementT,
    columns: Vec<String>,
    table_name: String,
    predicate: Predicate,
    schema: Schema,
}

impl Statement {
    fn parse_type(&mut self, tok_index: &mut usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        if *tok_index < self.toks.tok_list.len() {
            let first_tok = get_res(&self.toks.tok_list, *tok_index)?;
            self.toks
                .expect_tok_t(&first_tok.tok_t, vec![TokenT::Ident])?;
            let val = &first_tok.val;
            self.statement_t = if val == "insert" {
                let next_word_res = get_res(&self.toks.tok_list, *tok_index + 1);
                if next_word_res.is_err() {
                    result = Err(format!("{}: expected 'into' after insert", crate::function!()).into());
                }
                StatementT::Insert
            } else if val == "select" {
                StatementT::Select
            } else if val == "update" {
                StatementT::Update
            } else if val == "create" {
                StatementT::Create
            }  else {
                result = Err(format!(
                    "{}: did not expect '{}' as statement type string",
                    crate::function!(),
                    val
                )
                .into());
                StatementT::Error
            };
            *tok_index += 1;
        } else {
            result = Err(format!("{}: can not find statement type", crate::function!()).into());
        }
        return result;
    }

    fn parse_select_columns(
        &mut self,
        tok_index: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("{}: called", crate::function!());
        let mut result = Ok(());
        let mut must_be_ident = true;
        let mut reached_keyword = false;
        let start_index = *tok_index;
        while self.toks.tok_left(*tok_index)? == true && reached_keyword == false {
            let tok = get_res(&self.toks.tok_list, *tok_index)?;
            let tok_t = &tok.tok_t;
            debug!(
                "{}: tok: {}",
                crate::function!(),
                serde_json::to_string(&tok)?
            );
            trace!(
                "{}: self.keywords: {}",
                crate::function!(),
                serde_json::to_string(&self.keywords)?
            );
            if tok.tok_t == TokenT::Ident && self.keywords.contains(&tok.val) {
                debug!("{}: reached_keyword", crate::function!());
                reached_keyword = true;
            }
            if !reached_keyword {
                if must_be_ident {
                    self.toks.expect_tok_t(tok_t, vec![TokenT::Ident])?;
                    self.columns.push(tok.val.to_owned());
                } else {
                    self.toks.expect_tok_t(tok_t, vec![TokenT::Comma])?;
                }
                must_be_ident = !must_be_ident;
                *tok_index += 1;
            }
        }
        debug!(
            "{}: columns: {}",
            crate::function!(),
            self.columns.join(" ")
        );
        debug!("{}: returning", crate::function!());
        if *tok_index == start_index {
            result =
                Err(format!("{}: column names missing", crate::function!()).into());
        }
        return result;
    }

    fn skip_word(
        &self,
        tok_index: &mut usize,
        word: &String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        if *tok_index < self.toks.tok_list.len() {
            let tok = get_res(&self.toks.tok_list, *tok_index)?;
            self.toks
                .expect_tok_t(&tok.tok_t, vec![TokenT::Ident])?;
            self.toks.expect_val(tok, word)?;
            *tok_index += 1;
        } else {
            result = Err(format!("{}: expected '{}'", crate::function!(), word).into());
        }
        return result;
    }

    fn parse_table_name(
        &mut self,
        tok_index: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        let start_index = *tok_index;
        if *tok_index < self.toks.tok_list.len() {
            let tok = get_res(&self.toks.tok_list, *tok_index)?;
            self.toks.expect_not_keyword(&tok, &self.keywords)?;
            self.toks
                .expect_tok_t(&tok.tok_t, vec![TokenT::Ident])?;
            self.table_name = tok.val.to_owned();
            *tok_index += 1;
        }
        if *tok_index == start_index {
            result =
                Err(format!("{}: table name not found", crate::function!()).into());
        } else if *tok_index < self.toks.tok_list.len() {
            self.toks.expect_keyword(
                get_res(&self.toks.tok_list, *tok_index)?,
                &self.keywords,
            )?;
        }
        return result;
    }

    fn parse_comparison(
        &mut self,
        tok_index: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut result = Ok(());
        let mut cur_tok;
        let mut operator = TokenT::Error;
        let mut column_name = String::new();
        let mut has_comp = false;
        let mut is_err = false;
        if *tok_index < self.toks.tok_list.len() {
            cur_tok = get_res(&self.toks.tok_list, *tok_index)?;
            self.toks
                .expect_tok_t(&cur_tok.tok_t, vec![TokenT::Ident])?;
            column_name = cur_tok.val.to_owned();
            has_comp = true;
            *tok_index += 1;
        }
        if *tok_index < self.toks.tok_list.len() {
            cur_tok = get_res(&self.toks.tok_list, *tok_index)?;
            self.toks.expect_tok_t(
                &cur_tok.tok_t,
                vec![
                    TokenT::Greater,
                    TokenT::GreaterEq,
                    TokenT::Less,
                    TokenT::LessEq,
                    TokenT::Eq,
                ],
            )?;
            operator = cur_tok.tok_t.to_owned();
            *tok_index += 1;
        } else if has_comp == true {
            is_err = true;
        }
        if *tok_index < self.toks.tok_list.len() {
            cur_tok = get_res(&self.toks.tok_list, *tok_index)?;
            self.toks
                .expect_tok_t(&cur_tok.tok_t, vec![TokenT::Num])?;
            let number = cur_tok.val.to_owned();
            self.predicate.comparisons.push(Comparison {
                column_name,
                operator,
                number,
            });
            *tok_index += 1;
        } else if has_comp == true {
            is_err = true;
        }
        if is_err == true {
            result = Err(format!("{}: unexpected extra tokens", crate::function!()).into());
        }
        return result;
    }

    fn parse_predicate(
        &mut self,
        tok_index: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("{}: called", crate::function!());
        let mut result = Ok(());
        let start_index = *tok_index;
        self.parse_comparison(tok_index)?;
        if *tok_index == start_index {
            debug!(
                "{}: tok_index == start_index",
                crate::function!()
            );
            result = Err(format!(
                "{}: empty where clause not allowed",
                crate::function!()
            )
            .into());
        }
        return result;
    }

    fn parse_select(&mut self, tok_index: &mut usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut res = Ok(());
        self.parse_select_columns(tok_index)?;
        self.skip_word(tok_index, &"from".to_string())?;
        self.parse_table_name(tok_index)?;
        if self.toks.tok_left(*tok_index)? {
            let where_tok = get_res(&self.toks.tok_list, *tok_index)?;
            if where_tok.tok_t == TokenT::Ident && where_tok.val == "where" {
                *tok_index += 1;
                self.parse_predicate(tok_index)?;
            } else {
                res = Err(format!("{}: unexpected tokens", crate::function!()).into());
            }
        }
        return res;
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
        if index != self.toks.tok_list.len() {
            res = Err(format!(
                "{}: expected end of input",
                crate::function!()
            )
            .into());
        }
        return res;
    }

    fn parse_schema(
        &mut self,
        tok_idx: &mut usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut res = Ok(());
        let mut saw_primary = false;

        loop {
            let mut col_info = ColumnInfo{name: String::new(),
                data_t: SqlT::Error, constraints: vec![]};
            if self.toks.tok_left(*tok_idx)? {
                let col_name_tok = get_res(&self.toks.tok_list, *tok_idx)?;
                self.toks
                    .expect_tok_t(&col_name_tok.tok_t, vec![TokenT::Ident])?;
                self.toks
                    .expect_not_keyword(col_name_tok, &self.keywords)?;
                col_info.name = col_name_tok.val.to_string();
                *tok_idx += 1;
            }

            if self.toks.tok_left(*tok_idx)? {
                let col_type_tok = get_res(&self.toks.tok_list, *tok_idx)?;
                self.toks
                    .expect_tok_t(&col_type_tok.tok_t, vec![TokenT::Ident])?;
                if col_type_tok.val != "varchar" {
                    col_info.data_t = SqlT::from_str(&col_type_tok.val, 0)?;
                } else {
                    *tok_idx += 1;
                    if self.toks.tok_left(*tok_idx)? {
                        let lparen_tok = get_res(&self.toks.tok_list, *tok_idx)?;
                        self.toks.expect_tok_t(&lparen_tok.tok_t, vec![TokenT::LParen])?;
                    }
                    *tok_idx += 1;
                    if self.toks.tok_left(*tok_idx)? {
                        let int_tok = get_res(&self.toks.tok_list, *tok_idx)?;
                        self.toks.expect_tok_t(&int_tok.tok_t, vec![TokenT::Num])?;
                        let n_char = int_tok.val.parse::<usize>().unwrap();
                        col_info.data_t = SqlT::from_str(&col_type_tok.val, n_char)?;
                    }
                    *tok_idx += 1;
                    if self.toks.tok_left(*tok_idx)? {
                        let rparen = get_res(&self.toks.tok_list, *tok_idx)?;
                        self.toks.expect_tok_t(&rparen.tok_t, vec![TokenT::RParen])?;
                    }
                }
                *tok_idx += 1;
            }
            let old_tok_idx = *tok_idx;
            if self.toks.tok_left(*tok_idx)? {
                let primary_tok = get_res(&self.toks.tok_list, *tok_idx)?;
                if primary_tok.tok_t == TokenT::Ident && primary_tok.val == "primary" {
                    *tok_idx += 1;
                    if self.toks.tok_left(*tok_idx)? {
                        let key_tok = get_res(&self.toks.tok_list, *tok_idx)?;
                        if key_tok.tok_t == TokenT::Ident && key_tok.val == "key" {
                            if saw_primary != true {
                                *tok_idx += 1;
                                saw_primary = true;
                                col_info.constraints.push(ColumnConstraint::PrimaryKey);
                            } else {
                                res = Err(format!("{}: multiple 'primary key's", crate::function!()).into());
                            }
                        } else {
                            res = Err(format!("{}: expected 'key' after 'primary'", crate::function!()).into());
                        }
                    }
                }
            }
            if res.is_err() {
                break;
            }
            if saw_primary == false {
                *tok_idx = old_tok_idx;
            }
            self.schema.column_info_list.push(col_info);
            if self.toks.tok_left(*tok_idx)? {
                let comma = get_res(&self.toks.tok_list, *tok_idx)?;
                if comma.tok_t != TokenT::RParen {
                    self.toks.expect_tok_t(&comma.tok_t, vec![TokenT::Comma])?;
                } else {
                    *tok_idx += 1;
                    break;
                }

                *tok_idx += 1;
            }

            if self.toks.tok_left(*tok_idx)? == false {
                res = Err(format!("{}: unexpected end of input", crate::function!()).into());
                break;
            }
        }

        return res;
    }

    fn parse_create(&mut self, tok_index: &mut usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut res = Ok(());

        self.skip_word(tok_index, &"table".to_string())?;

        if self.toks.tok_left(*tok_index)? {
            let table_name_tok = get_res(&self.toks.tok_list, *tok_index)?;
            self.toks
                .expect_tok_t(&table_name_tok.tok_t, vec![TokenT::Ident])?;
            self.toks
                .expect_not_keyword(table_name_tok, &self.keywords)?;
            self.table_name = table_name_tok.val.to_owned();
            *tok_index += 1;
        } else {
            res = Err(format!("{}: table name is missing", crate::function!()).into());
        }

        println!("tok_index: {}", *tok_index);
        println!("tok count: {}", self.toks.tok_list.len());
        if self.toks.tok_left(*tok_index)? {
            let left_paren_tok = get_res(&self.toks.tok_list, *tok_index)?;
            self.toks
                .expect_tok_t(&left_paren_tok.tok_t, vec![TokenT::LParen])?;
            *tok_index += 1;
        } else if res.is_ok() {
            res = Err(format!("{}: schema is missing", crate::function!()).into());
        }

        if self.toks.tok_left(*tok_index)? {
            self.parse_schema(tok_index)?;
            println!("after parse_column_info");
        } else if res.is_ok() {
            res = Err(format!(
                "{}: expected something after left paren",
                crate::function!()
            )
            .into());
        }

        return res;
    }

    fn parse(statement_str: &String) -> Result<Statement, Box<dyn std::error::Error>> {
        let mut statement = Statement {
            toks: Tokens::tokize(&statement_str.to_ascii_lowercase())?,
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
        let mut err = false;
        let mut err_msg = String::new();
        statement.init_keyword_strings()?;
        let mut tok_index = 0;
        statement.parse_type(&mut tok_index)?;
        if statement.statement_t == StatementT::Insert {
            err = true;
            err_msg = format!("{}: 'insert' is not supported", crate::function!()).to_string();
        } else if statement.statement_t == StatementT::Select {
            statement.parse_select(&mut tok_index)?;
        } else if statement.statement_t == StatementT::Update {
            err = true;
            err_msg = format!("{}: 'update' is not supported", crate::function!()).to_string();
        } else if statement.statement_t == StatementT::Create {
            statement.parse_create(&mut tok_index)?;
        }
        if err == false {
            statement.expect_end(tok_index)?;
        }
        let res = if err == true {
            Err(err_msg.into())
        } else {
            Ok(statement)
        };
        return res;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Type 'q' to exit");

    loop {
        print!("> ");
        std::io::stdout().flush().unwrap();

        let mut line = String::new();
        let stdin = std::io::stdin();
        stdin.lock().read_line(&mut line).unwrap();

        if line == "q\n" {
            break;
        }

        let statement_res = Statement::parse(&line.to_string());

        if statement_res.is_ok() {
            println!("{}", serde_json::to_string_pretty(&statement_res?)?);
        } else {
            println!("{}", statement_res.err().unwrap());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::get_res;
    use crate::Comparison;
    use crate::Predicate;
    use crate::Statement;
    use crate::StatementT;
    use crate::Token;
    use crate::TokenT;
    use crate::Tokens;

    impl Tokens {
    fn eq(&self, other: &Tokens) -> Result<bool, Box<dyn std::error::Error>> {
        let mut is_eq = true;
        if self.tok_list.len() != other.tok_list.len() {
            is_eq = false;
        }
        let mut i = 0;
        while i < self.tok_list.len() && is_eq {
            if get_res(&self.tok_list, i)? != get_res(&other.tok_list, i)? {
                is_eq = false;
            }
            i += 1;
        }
        return Ok(is_eq);
    }
    }

    fn test_tokize() -> Result<(), Box<dyn std::error::Error>> {
        let mut toks_res;
        let mut expected;
        let mut eq_res;

        toks_res = Tokens::tokize(&"select name from table_1".to_string());
        assert!(toks_res.is_ok() == true);
        expected = Tokens {
            tok_list: vec![
                Token {
                    tok_t: TokenT::Ident,
                    val: "select".to_string(),
                },
                Token {
                    tok_t: TokenT::Ident,
                    val: "name".to_string(),
                },
                Token {
                    tok_t: TokenT::Ident,
                    val: "from".to_string(),
                },
                Token {
                    tok_t: TokenT::Ident,
                    val: "table_1".to_string(),
                },
            ],
            stream: Vec::new(),
        };
        eq_res = toks_res.as_ref().unwrap().eq(&expected);
        assert!(eq_res.is_ok() == true);
        assert!(eq_res.unwrap() == true);

        toks_res = Tokens::tokize(
            &"select column1, column2, column3\nfrom table_name\nwhere column1 > 500\n\n"
                .to_string()
        );
        if toks_res.is_err() {
            debug!(
                "{}: toks_res error: {}",
                crate::function!(),
                toks_res.as_ref().err().unwrap()
            );
        }
        assert!(toks_res.is_ok() == true);
        expected = Tokens {
            tok_list: vec![
                Token {
                    tok_t: TokenT::Ident,
                    val: "select".to_string(),
                },
                Token {
                    tok_t: TokenT::Ident,
                    val: "column1".to_string(),
                },
                Token {
                    tok_t: TokenT::Comma,
                    val: String::new(),
                },
                Token {
                    tok_t: TokenT::Ident,
                    val: "column2".to_string(),
                },
                Token {
                    tok_t: TokenT::Comma,
                    val: String::new(),
                },
                Token {
                    tok_t: TokenT::Ident,
                    val: "column3".to_string(),
                },
                Token {
                    tok_t: TokenT::Ident,
                    val: "from".to_string(),
                },
                Token {
                    tok_t: TokenT::Ident,
                    val: "table_name".to_string(),
                },
                Token {
                    tok_t: TokenT::Ident,
                    val: "where".to_string(),
                },
                Token {
                    tok_t: TokenT::Ident,
                    val: "column1".to_string(),
                },
                Token {
                    tok_t: TokenT::Greater,
                    val: String::new(),
                },
                Token {
                    tok_t: TokenT::Num,
                    val: "500".to_string(),
                },
            ],
            stream: Vec::new(),
        };
        eq_res = toks_res.as_ref().unwrap().eq(&expected);
        assert!(eq_res.is_ok() == true);
        assert!(eq_res.unwrap() == true);
        return Ok(());
    }

    fn test_parse() -> Result<(), Box<dyn std::error::Error>> {
        let mut query;
        let mut parse_res;
        let mut statement;

        query = "select name from table_1".to_string();
        parse_res = Statement::parse(&query);
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
        parse_res = Statement::parse(&query);
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
        parse_res = Statement::parse(&query);
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_res error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name from table_1 something".to_string();
        parse_res = Statement::parse(&query);
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name from table_1 where name = 400 something".to_string();
        parse_res = Statement::parse(&query);
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name from table_1 where name = 400 1".to_string();
        parse_res = Statement::parse(&query);
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select from table_1 where name = 400".to_string();
        parse_res = Statement::parse(&query);
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name from where name = 400".to_string();
        parse_res = Statement::parse(&query);
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name from table_name where".to_string();
        parse_res = Statement::parse(&query);
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        query = "select name form table_name".to_string();
        parse_res = Statement::parse(&query);
        assert!(parse_res.is_err() == true);
        trace!(
            "{}: parse_err error: {}",
            crate::function!(),
            parse_res.err().unwrap()
        );

        return Ok(());
    }

    fn test_toks() -> Result<(), Box<dyn std::error::Error>> {
        test_tokize()?;
        return Ok(());
    }

    fn test_statement() -> Result<(), Box<dyn std::error::Error>> {
        test_parse()?;
        return Ok(());
    }

    #[test]
    fn test() {
        env_logger::init();
        test_toks().expect("test_toks failed");
        test_statement().expect("test_statement failed");
    }
}
