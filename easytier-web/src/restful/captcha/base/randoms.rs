
use rand::{random};


/// 随机数工具类
pub(crate) struct Randoms {
    /// 定义验证码字符.去除了0、O、I、L等容易混淆的字母
    pub alpha: [char; 54],

    /// 数字的最大索引，不包括最大值
    pub num_max_index: usize,

    /// 字符的最小索引，包括最小值
    pub char_min_index: usize,

    /// 字符的最大索引，不包括最大值
    pub char_max_index: usize,

    /// 大写字符最小索引
    pub upper_min_index: usize,

    /// 大写字符最大索引
    pub upper_max_index: usize,

    /// 小写字母最小索引
    pub lower_min_index: usize,

    /// 小写字母最大索引
    pub lower_max_index: usize,
}

impl Randoms {
    pub fn new() -> Self {
        // Defines the Captcha characters, removing characters like 0, O, I, l, etc.
        let alpha = [
            '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J',
            'K', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
            'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
            'x', 'y', 'z',
        ];

        let num_max_index = 8;
        let char_min_index = num_max_index;
        let char_max_index = alpha.len();
        let upper_min_index = char_min_index;
        let upper_max_index = upper_min_index + 23;
        let lower_min_index = upper_max_index;
        let lower_max_index = char_max_index;

        Self {
            alpha,
            num_max_index,
            char_min_index,
            char_max_index,
            upper_min_index,
            upper_max_index,
            lower_min_index,
            lower_max_index,
        }
    }

    /// 产生两个数之间的随机数
    pub fn num_between(&mut self, min: i32, max: i32) -> i32 {
        min + (random::<usize>() % (max - min) as usize) as i32
    }

    /// 产生0-num的随机数,不包括num
    pub fn num(&mut self, num: usize) -> usize {
        random::<usize>() % num
    }

    /// 返回ALPHA中的随机字符
    pub fn alpha(&mut self) -> char {
        self.alpha[self.num(self.alpha.len())]
    }

    /// 返回ALPHA中第0位到第num位的随机字符
    pub fn alpha_under(&mut self, num: usize) -> char {
        self.alpha[self.num(num)]
    }

    /// 返回ALPHA中第min位到第max位的随机字符
    pub fn alpha_between(&mut self, min: usize, max: usize) -> char {
        self.alpha[self.num_between(min as i32, max as i32) as usize]
    }
}
