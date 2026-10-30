use serde::{Deserialize, Serialize};

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    #[default]
    PlainText,
    Url,
    Email,
    HexColor,
    Json,
    Code,
    Number,
}

impl ContentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentType::PlainText => "plain_text",
            ContentType::Url => "url",
            ContentType::Email => "email",
            ContentType::HexColor => "hex_color",
            ContentType::Json => "json",
            ContentType::Code => "code",
            ContentType::Number => "number",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "url" => ContentType::Url,
            "email" => ContentType::Email,
            "hex_color" => ContentType::HexColor,
            "json" => ContentType::Json,
            "code" => ContentType::Code,
            "number" => ContentType::Number,
            _ => ContentType::PlainText,
        }
    }

    /// 数据库内以整数存储（比字符串省 9 字节/行，且可建复合索引）。
    /// 编号一旦发布不得改动——它是落盘格式的一部分。
    pub fn to_db_i64(&self) -> i64 {
        match self {
            ContentType::PlainText => 0,
            ContentType::Url => 1,
            ContentType::Email => 2,
            ContentType::HexColor => 3,
            ContentType::Json => 4,
            ContentType::Code => 5,
            ContentType::Number => 6,
        }
    }

    pub fn from_db_i64(v: i64) -> Self {
        match v {
            1 => ContentType::Url,
            2 => ContentType::Email,
            3 => ContentType::HexColor,
            4 => ContentType::Json,
            5 => ContentType::Code,
            6 => ContentType::Number,
            _ => ContentType::PlainText,
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentAnalysis {
    pub content_type: ContentType,
    pub char_count: u64,
    pub line_count: u64,
    pub byte_count: u64,
    pub preview: String,
}

/// Formats a multi-line or long string into a single-line preview.
pub fn format_preview(s: &str, max_chars: usize) -> String {
    let single_line = s
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    if single_line.is_empty() {
        return "(空白)".to_string();
    }

    let char_count = single_line.chars().count();
    if char_count > max_chars {
        let take_n = max_chars.saturating_sub(3).max(1);
        let truncated: String = single_line.chars().take(take_n).collect();
        format!("{}...", truncated)
    } else {
        single_line
    }
}

pub fn detect_content_type(s: &str) -> ContentType {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return ContentType::PlainText;
    }

    // 1. Hex Color / RGB
    if (trimmed.starts_with('#')
        && (trimmed.len() == 4 || trimmed.len() == 7 || trimmed.len() == 9))
        && trimmed[1..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return ContentType::HexColor;
    }
    if (trimmed.starts_with("rgb(") || trimmed.starts_with("rgba(")) && trimmed.ends_with(')') {
        return ContentType::HexColor;
    }

    // 2. URL
    if (trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("ftp://"))
        && !trimmed.contains(char::is_whitespace)
    {
        return ContentType::Url;
    }

    // 3. Email
    if !trimmed.contains(char::is_whitespace) && trimmed.contains('@') {
        let parts: Vec<&str> = trimmed.split('@').collect();
        if parts.len() == 2
            && !parts[0].is_empty()
            && parts[1].contains('.')
            && !parts[1].ends_with('.')
        {
            return ContentType::Email;
        }
    }

    // 4. Number
    if trimmed.parse::<f64>().is_ok() {
        return ContentType::Number;
    }

    // 5. JSON
    if (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
    {
        if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
            return ContentType::Json;
        }
    }

    // 6. Code check
    let line_count = s.lines().count();
    let has_code_keywords = trimmed.contains("fn ")
        || trimmed.contains("def ")
        || trimmed.contains("class ")
        || trimmed.contains("import ")
        || trimmed.contains("public ")
        || trimmed.contains("return ")
        || trimmed.contains("let ")
        || trimmed.contains("const ")
        || trimmed.contains("var ")
        || trimmed.contains("=>")
        || trimmed.contains("</")
        || trimmed.contains("/>");

    if (line_count > 1 && has_code_keywords)
        || (has_code_keywords && (trimmed.contains('{') || trimmed.contains(';')))
    {
        return ContentType::Code;
    }

    ContentType::PlainText
}

pub fn analyze_content(s: &str) -> ContentAnalysis {
    let char_count = s.chars().count() as u64;
    let line_count = s.lines().count().max(1) as u64;
    let byte_count = s.len() as u64;
    let content_type = detect_content_type(s);
    let preview = format_preview(s, 80);

    ContentAnalysis {
        content_type,
        char_count,
        line_count,
        byte_count,
        preview,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_preview() {
        let text = "First line\nSecond line\n\nThird line";
        assert_eq!(
            format_preview(text, 50),
            "First line Second line Third line"
        );

        let long_text = "a".repeat(100);
        let preview = format_preview(&long_text, 10);
        assert_eq!(preview.chars().count(), 10);
        assert!(preview.ends_with("..."));

        assert_eq!(format_preview("   ", 50), "(空白)");
    }

    #[test]
    fn test_detect_content_type() {
        assert_eq!(detect_content_type("#ff5733"), ContentType::HexColor);
        assert_eq!(detect_content_type("#FFF"), ContentType::HexColor);
        assert_eq!(
            detect_content_type("https://github.com/rust-lang"),
            ContentType::Url
        );
        assert_eq!(detect_content_type("user@example.com"), ContentType::Email);
        assert_eq!(detect_content_type("12345.67"), ContentType::Number);
        assert_eq!(
            detect_content_type("{\"key\": \"value\"}"),
            ContentType::Json
        );
        assert_eq!(
            detect_content_type("fn main() {\n    println!(\"Hello\");\n}"),
            ContentType::Code
        );
        assert_eq!(
            detect_content_type("Just a normal text note."),
            ContentType::PlainText
        );
    }
}
