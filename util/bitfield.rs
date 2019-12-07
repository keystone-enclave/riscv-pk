#[macro_export]
macro_rules! insert_field {
    ($val:expr, $which:expr, $fieldval:expr) => (
        (($val & !$which) | ($fieldval * ($which & !($which-1))))
    )
}
