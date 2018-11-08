##! Add SNI info to the SSL record

export 
{
    # Adding a vector of SNI names to the standard SSL log
    redef record SSL::Info += {
        SNI: string_vec &optional &log;
    };
}

# Hook the ssl_extension_server_name event to receive data any time the Server Name
# extension is available. Add the name to the standard SSL log.
event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
{
     c$ssl$SNI = names;
}
